"""Core Asynchronous Orchestration and Intelligence Correlation Engine."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from config import settings

from core.models import (
    Finding,
    FindingType,
    HostInfoData,
    HostResult,
    PortData,
    ScanResult,
    SeverityLevel,
    VulnerabilityData,
)
from modules.base import BaseModule
from modules.censys import CensysModule
from modules.crtsh import CrtshModule
from modules.exploitdb import ExploitDBModule
from modules.nvd import NVDModule
from modules.reverse_whois import ReverseWhoisModule
from modules.shodan import ShodanModule
from utils.http import AsyncHTTPClient, http_client

logger = logging.getLogger("detecti.engine")


def _clean_source(src: str) -> str:
    """Normalize source names (e.g. 'Censys Platform v3' -> 'Censys', 'Shodan DNS' -> 'Shodan')."""
    if not src:
        return "Unknown"
    lower = src.lower()
    if "shodan" in lower:
        return "Shodan"
    if "censys" in lower:
        return "Censys"
    if "crtsh" in lower or "crt.sh" in lower:
        return "crt.sh"
    if "whois" in lower:
        return "Reverse WHOIS"
    return src


class ThreatTrackEngine:
    """Async execution runner orchestrating modules, target classification, and correlation."""

    MODULE_REGISTRY: Dict[str, type[BaseModule]] = {
        "shodan": ShodanModule,
        "censys": CensysModule,
        "crtsh": CrtshModule,
        "reverse_whois": ReverseWhoisModule,
        "nvd": NVDModule,
        "exploitdb": ExploitDBModule,
    }

    def __init__(
        self,
        client: Optional[AsyncHTTPClient] = None,
        progress_callback: Optional[Callable[[str, str], None]] = None,
    ):
        self.http_client = client or http_client
        self.progress_callback = progress_callback
        self.modules: Dict[str, BaseModule] = {
            name: cls(client=self.http_client)
            for name, cls in self.MODULE_REGISTRY.items()
        }

    def _notify(self, module_name: str, message: str) -> None:
        if self.progress_callback:
            self.progress_callback(module_name, message)
        logger.info(f"[{module_name}] {message}")

    def classify_target(self, target: str) -> str:
        """Identify target classification (ip, cidr, domain, cve, query, file, email)."""
        target = target.strip()
        if target.startswith("file:") or (Path(target).is_file() and not target.startswith("http")):
            return "file"
        if target.startswith("host:"):
            inner = target[5:]
            return "cidr" if "/" in inner else "ip"
        if target.startswith("domain:"):
            return "domain"
        if target.upper().startswith("CVE-"):
            return "cve"
        if "@" in target:
            return "email"

        if "/" in target:
            try:
                ipaddress.ip_network(target, strict=False)
                return "cidr"
            except ValueError:
                pass

        try:
            ipaddress.ip_address(target)
            return "ip"
        except ValueError:
            pass

        if "." in target and " " not in target and ":" not in target:
            return "domain"

        return "query"

    async def verify_environment_apis(self, enabled_modules: Optional[List[str]] = None) -> Dict[str, Dict[str, Any]]:
        """Verify API keys present in the environment/config and perform non-blocking pre-flight checks."""
        active_mod_names = (
            [m for m in enabled_modules if m in self.modules]
            if enabled_modules and "all" not in enabled_modules
            else list(self.modules.keys())
        )
        
        status_report: Dict[str, Dict[str, Any]] = {}

        # 1. Shodan
        if "shodan" in active_mod_names:
            shodan_mod: ShodanModule = self.modules["shodan"]  # type: ignore
            if shodan_mod.is_configured():
                is_valid = await shodan_mod.validate_credentials()
                status_report["shodan"] = {
                    "name": "Shodan",
                    "configured": True,
                    "valid": is_valid,
                    "status": "Active & Valid" if is_valid else "Invalid Credentials (Bypassed)",
                    "tier": "Standard API",
                }
            else:
                status_report["shodan"] = {
                    "name": "Shodan",
                    "configured": False,
                    "valid": False,
                    "status": "Not Configured (Required for Shodan recon)",
                    "tier": "None",
                }

        # 2. Censys
        if "censys" in active_mod_names:
            censys_mod: CensysModule = self.modules["censys"]  # type: ignore
            if censys_mod.is_configured():
                is_valid = await censys_mod.validate_credentials()
                status_report["censys"] = {
                    "name": "Censys",
                    "configured": True,
                    "valid": is_valid,
                    "status": "Active & Valid" if is_valid else "Invalid / Unauthorized (Bypassed)",
                    "tier": "PAT Token" if censys_mod.pat_token else "Legacy API",
                }
            else:
                status_report["censys"] = {
                    "name": "Censys",
                    "configured": False,
                    "valid": False,
                    "status": "Not Configured / Placeholder (Bypassed)",
                    "tier": "None",
                }

        # 3. NVD
        if "nvd" in active_mod_names:
            nvd_mod: NVDModule = self.modules["nvd"]  # type: ignore
            if nvd_mod.is_configured():
                status_report["nvd"] = {
                    "name": "NVD (NIST)",
                    "configured": True,
                    "valid": True,
                    "status": "Active (High-speed 0.6s rate limit)",
                    "tier": "API Key",
                }
            else:
                status_report["nvd"] = {
                    "name": "NVD (NIST)",
                    "configured": False,
                    "valid": True,
                    "status": "Active (Public mode, 6.0s rate limit)",
                    "tier": "Free / Public",
                }

        # 4. WhoisFreaks / Reverse WHOIS
        if "reverse_whois" in active_mod_names:
            whois_mod: ReverseWhoisModule = self.modules["reverse_whois"]  # type: ignore
            if whois_mod.is_configured():
                status_report["reverse_whois"] = {
                    "name": "WhoisFreaks",
                    "configured": True,
                    "valid": True,
                    "status": "Active (WhoisFreaks API)",
                    "tier": "Paid API",
                }
            else:
                status_report["reverse_whois"] = {
                    "name": "WhoisFreaks",
                    "configured": False,
                    "valid": True,
                    "status": "Active (HackerTarget / RDAP Fallback)",
                    "tier": "Free OSINT",
                }

        # 5. ExploitDB / GitHub Token
        if "exploitdb" in active_mod_names:
            from config import is_placeholder_key
            has_gh = bool(settings.github_token and not is_placeholder_key(settings.github_token))
            status_report["exploitdb"] = {
                "name": "ExploitDB / GitHub PoCs",
                "configured": has_gh,
                "valid": True,
                "status": "Active (Local ExploitDB + Authenticated GitHub PoCs)" if has_gh else "Active (Local ExploitDB + Public PoC API)",
                "tier": "GitHub Token" if has_gh else "Public PoC API",
            }

        return status_report

    async def scan(
        self,
        target: str,
        enabled_modules: Optional[List[str]] = None,
        cvss_filter: Optional[str] = None,
    ) -> ScanResult:
        """Run complete scan pipeline organized per host and domain."""
        target = target.strip()
        start_time = time.monotonic()
        target_type = self.classify_target(target)

        # Handle file input containing multiple targets
        if target_type == "file":
            file_path = target[5:] if target.startswith("file:") else target
            return await self._scan_file(file_path, enabled_modules, cvss_filter)

        active_mod_names = (
            [m for m in enabled_modules if m in self.modules]
            if enabled_modules and "all" not in enabled_modules
            else list(self.modules.keys())
        )

        # Pre-flight API verification layer: validate all APIs present in environment/config
        self._notify("engine", "Verifying environment API credentials and endpoints...")
        await self.verify_environment_apis(active_mod_names)

        result = ScanResult(
            target=target,
            target_type=target_type,
            started_at=datetime.now(timezone.utc),
            modules_run=active_mod_names,
        )

        context: Dict[str, Any] = {"target": target, "target_type": target_type, "cves": set()}
        raw_recon_findings: List[Finding] = []

        # ----------------------------------------------------
        # Stage 1: Recon & Discovery (Shodan Primary Query, Censys, crt.sh, Reverse WHOIS)
        # ----------------------------------------------------
        recon_tasks = []
        is_direct_ip = (target_type == "ip")
        has_shodan = "shodan" in active_mod_names and self.modules["shodan"].is_configured()
        has_censys = "censys" in active_mod_names and self.modules["censys"].is_configured()

        if target_type == "cve":
            context["cves"].add(target.upper())
        else:
            # 1. Shodan Search / Host Lookup
            if has_shodan:
                self._notify("shodan", f"Querying Shodan for {target}...")
                recon_tasks.append(self.modules["shodan"].run(target, context))

            # 2. Censys Direct Host Lookup (Executed in Stage 1 for direct IP targets, or as fallback if Shodan is not configured)
            if has_censys and (is_direct_ip or not has_shodan):
                self._notify("censys", f"Querying Censys for {target}...")
                recon_tasks.append(self.modules["censys"].run(target, context))

            # 3. Certificate Transparency
            if target_type in ("domain", "email") and "crtsh" in active_mod_names:
                self._notify("crtsh", f"Querying Certificate Transparency for {target}...")
                recon_tasks.append(self.modules["crtsh"].run(target, context))

            # 4. Reverse WHOIS
            if target_type in ("domain", "ip", "email") and "reverse_whois" in active_mod_names:
                self._notify("reverse_whois", f"Performing Reverse WHOIS lookup for {target}...")
                recon_tasks.append(self.modules["reverse_whois"].run(target, context))

        if recon_tasks:
            recon_results = await asyncio.gather(*recon_tasks, return_exceptions=True)
            for res in recon_results:
                if isinstance(res, list):
                    raw_recon_findings.extend(res)
                elif isinstance(res, Exception):
                    logger.error(f"Error during recon stage: {res}")

        # ----------------------------------------------------
        # Stage 1.5: Complementary Censys Host Enrichment for All Discovered IPs
        # (Enrich all IPs discovered from DNS/crt.sh/Shodan with Censys port & service dossiers)
        # ----------------------------------------------------
        if has_censys and target_type != "cve":
            # Extract all unique host IPs discovered that haven't had a full Censys host lookup yet
            already_queried_censys_ips = {
                f.host_ip for f in raw_recon_findings if f.host_ip and "censys" in f.source.lower() and f.type == FindingType.HOST_INFO
            }
            all_discovered_ips = set()
            for f in raw_recon_findings:
                hip = f.host_ip or (f.host_info.ip if f.host_info else None)
                if hip and hip not in already_queried_censys_ips:
                    all_discovered_ips.add(hip)

            enrichment_ips = list(all_discovered_ips)
            if enrichment_ips:
                self._notify("censys", f"Enriching all {len(enrichment_ips)} discovered host IPs with Censys port & service dossiers...")
                censys_mod: CensysModule = self.modules["censys"]  # type: ignore
                censys_tasks = [censys_mod.get_host_info(ip) for ip in enrichment_ips]
                censys_results = await asyncio.gather(*censys_tasks, return_exceptions=True)
                for res in censys_results:
                    if isinstance(res, list):
                        raw_recon_findings.extend(res)
                    elif isinstance(res, Exception):
                        logger.debug(f"Censys host enrichment exception: {res}")

        # ----------------------------------------------------
        # Group Discoveries per Host
        # ----------------------------------------------------
        hosts_map: Dict[str, HostResult] = {}
        host_cves_map: Dict[str, Set[str]] = {}
        all_unique_cves: Set[str] = set(context["cves"])
        domain_findings: List[Finding] = []

        for f in raw_recon_findings:
            clean_src = _clean_source(f.source)

            if f.type in (FindingType.SUBDOMAIN, FindingType.ASSOCIATED_DOMAIN) and not f.host_ip:
                domain_findings.append(f)
                continue

            host_ip = f.host_ip or (f.host_info.ip if f.host_info else None)
            if not host_ip and f.type == FindingType.VULNERABILITY and target_type == "cve":
                # Standalone CVE scan
                all_unique_cves.add(f.value.upper())
                continue

            if host_ip:
                if host_ip not in hosts_map:
                    hosts_map[host_ip] = HostResult(ip=host_ip)
                    host_cves_map[host_ip] = set()

                host_obj = hosts_map[host_ip]
                if clean_src and clean_src not in host_obj.sources:
                    host_obj.sources.append(clean_src)

                if f.type == FindingType.HOST_INFO and f.host_info:
                    hi = f.host_info
                    host_obj.hostnames = sorted(list(set(host_obj.hostnames + hi.hostnames)))
                    host_obj.domains = sorted(list(set(host_obj.domains + hi.domains)))
                    host_obj.org = hi.org or host_obj.org
                    host_obj.isp = hi.isp or host_obj.isp
                    host_obj.asn = hi.asn or host_obj.asn
                    host_obj.os = hi.os or host_obj.os
                    host_obj.country_name = hi.country_name or host_obj.country_name
                    host_obj.country_code = hi.country_code or host_obj.country_code
                    host_obj.city = hi.city or host_obj.city
                    host_obj.region_code = hi.region_code or host_obj.region_code
                    if hi.vulns:
                        for v in hi.vulns:
                            if v.upper().startswith("CVE-"):
                                host_cves_map[host_ip].add(v.upper())
                                all_unique_cves.add(v.upper())

                elif f.type == FindingType.OPEN_PORT and f.port_info:
                    pi = f.port_info
                    # Check for existing port on this host
                    matching_port = next(
                        (p for p in host_obj.ports if p.port == pi.port and p.transport.lower() == pi.transport.lower()),
                        None,
                    )
                    if matching_port:
                        # Complement and enrich existing port without duplicating
                        if clean_src and clean_src not in matching_port.sources:
                            matching_port.sources.append(clean_src)
                        for s in pi.sources:
                            clean_s = _clean_source(s)
                            if clean_s and clean_s not in matching_port.sources:
                                matching_port.sources.append(clean_s)

                        matching_port.product = matching_port.product or pi.product
                        matching_port.version = matching_port.version or pi.version
                        matching_port.service = matching_port.service or pi.service
                        matching_port.banner = matching_port.banner or pi.banner
                        matching_port.url = matching_port.url or pi.url
                        matching_port.ssl = matching_port.ssl or pi.ssl
                    else:
                        if clean_src and clean_src not in pi.sources:
                            pi.sources.append(clean_src)
                        host_obj.ports.append(pi)

                elif f.type == FindingType.VULNERABILITY:
                    cve = f.value.upper()
                    if cve.startswith("CVE-"):
                        host_cves_map[host_ip].add(cve)
                        all_unique_cves.add(cve)

                elif f.type == FindingType.SUBDOMAIN and f.value:
                    if f.value not in host_obj.hostnames:
                        host_obj.hostnames.append(f.value)

                elif f.type == FindingType.ASSOCIATED_DOMAIN and f.value:
                    if f.value not in host_obj.domains:
                        host_obj.domains.append(f.value)

        # ----------------------------------------------------
        # Stage 2: Threat Intelligence & Vulnerability Enrichment (NVD, EPSS, CISA KEV)
        # ----------------------------------------------------
        enriched_vulns: Dict[str, VulnerabilityData] = {}
        if all_unique_cves and "nvd" in active_mod_names:
            self._notify("nvd", f"Enriching {len(all_unique_cves)} CVEs with NVD, EPSS & CISA KEV...")
            nvd_mod: NVDModule = self.modules["nvd"]  # type: ignore
            await nvd_mod._ensure_cisa_kev_loaded()

            nvd_tasks = [nvd_mod.enrich_cve(cve) for cve in all_unique_cves]
            nvd_results = await asyncio.gather(*nvd_tasks, return_exceptions=True)

            for cve, vdata in zip(all_unique_cves, nvd_results):
                if isinstance(vdata, Exception):
                    logger.warning(f"Failed to enrich {cve}: {vdata}")
                elif isinstance(vdata, VulnerabilityData):
                    enriched_vulns[cve] = vdata

        # ----------------------------------------------------
        # Stage 3: Exploit & PoC Intelligence (ExploitDB + GitHub)
        # ----------------------------------------------------
        if all_unique_cves and "exploitdb" in active_mod_names:
            self._notify("exploitdb", f"Hunting exploits & GitHub PoCs for {len(all_unique_cves)} CVEs...")
            xdb_mod: ExploitDBModule = self.modules["exploitdb"]  # type: ignore
            xdb_tasks = [xdb_mod.get_exploits_for_cve(cve) for cve in all_unique_cves]
            xdb_results = await asyncio.gather(*xdb_tasks, return_exceptions=True)

            for cve, exps in zip(all_unique_cves, xdb_results):
                if isinstance(exps, list) and cve in enriched_vulns:
                    enriched_vulns[cve].exploits = exps

        # ----------------------------------------------------
        # Stage 4: Attach Enriched Vulnerabilities to Specific Hosts
        # ----------------------------------------------------
        for host_ip, host_obj in hosts_map.items():
            cves_for_this_host = host_cves_map.get(host_ip, set())
            host_vulns: List[VulnerabilityData] = []

            for cve in sorted(cves_for_this_host):
                if cve in enriched_vulns:
                    vdata = enriched_vulns[cve]
                    # Apply CVSS filter if requested
                    if cvss_filter:
                        if vdata.cvss_severity != cvss_filter.upper():
                            continue
                    host_vulns.append(vdata)

            # Sort host vulns by CVSS score descending
            host_vulns.sort(key=lambda x: (x.cvss_score or 0.0), reverse=True)
            host_obj.vulnerabilities = host_vulns

        # ----------------------------------------------------
        # Stage 5: Compile Final Findings & Output
        # ----------------------------------------------------
        final_findings: List[Finding] = []
        final_findings.extend(domain_findings)

        for host_ip, host_obj in hosts_map.items():
            host_sources_str = ", ".join(host_obj.sources) if host_obj.sources else "Recon"

            # Host finding
            final_findings.append(
                Finding(
                    type=FindingType.HOST_INFO,
                    target=target,
                    value=host_ip,
                    source=host_sources_str,
                    host_ip=host_ip,
                    host_info=HostInfoData(
                        ip=host_ip,
                        hostnames=host_obj.hostnames,
                        domains=host_obj.domains,
                        org=host_obj.org,
                        isp=host_obj.isp,
                        asn=host_obj.asn,
                        os=host_obj.os,
                        country_name=host_obj.country_name,
                        city=host_obj.city,
                        region_code=host_obj.region_code,
                        ports=[p.port for p in host_obj.ports],
                        vulns=[v.cve_id for v in host_obj.vulnerabilities],
                    ),
                )
            )

            # Port findings with combined sources
            for p in host_obj.ports:
                port_sources_str = ", ".join(dict.fromkeys(p.sources)) if p.sources else host_sources_str
                final_findings.append(
                    Finding(
                        type=FindingType.OPEN_PORT,
                        target=target,
                        value=f"{host_ip}:{p.port}",
                        source=port_sources_str,
                        host_ip=host_ip,
                        port_info=p,
                    )
                )

            # Vulnerability findings attached to this host
            for v in host_obj.vulnerabilities:
                final_findings.append(
                    Finding(
                        type=FindingType.VULNERABILITY,
                        target=target,
                        value=v.cve_id,
                        source="NVD+EPSS+CISA",
                        host_ip=host_ip,
                        vulnerability=v,
                    )
                )
                for exp in v.exploits:
                    final_findings.append(
                        Finding(
                            type=FindingType.EXPLOIT,
                            target=target,
                            value=f"{v.cve_id} - {exp.title}",
                            source=exp.source,
                            host_ip=host_ip,
                            exploit=exp,
                        )
                    )

        # Standalone CVE scan without hosts
        if not hosts_map and target_type == "cve":
            for cve, vdata in enriched_vulns.items():
                if cvss_filter and vdata.cvss_severity != cvss_filter.upper():
                    continue
                final_findings.append(
                    Finding(
                        type=FindingType.VULNERABILITY,
                        target=target,
                        value=cve,
                        source="NVD+EPSS+CISA",
                        vulnerability=vdata,
                    )
                )
                for exp in vdata.exploits:
                    final_findings.append(
                        Finding(
                            type=FindingType.EXPLOIT,
                            target=target,
                            value=f"{cve} - {exp.title}",
                            source=exp.source,
                            exploit=exp,
                        )
                    )

        result.hosts = list(hosts_map.values())
        result.findings = final_findings
        result.completed_at = datetime.now(timezone.utc)
        result.elapsed_seconds = time.monotonic() - start_time
        result.calculate_summary()

        self._notify("engine", f"Scan completed in {result.elapsed_seconds:.2f}s with {len(result.hosts)} hosts and {len(result.findings)} findings.")
        return result

    async def _scan_file(
        self,
        file_path: str,
        enabled_modules: Optional[List[str]],
        cvss_filter: Optional[str],
    ) -> ScanResult:
        """Process file containing targets line-by-line."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Input file not found: {file_path}")

        lines = [line.strip() for line in path.read_text().splitlines() if line.strip() and not line.startswith("#")]
        self._notify("engine", f"Loaded {len(lines)} targets from {file_path}")

        combined_result = ScanResult(
            target=file_path,
            target_type="file",
            started_at=datetime.now(timezone.utc),
            modules_run=enabled_modules or list(self.MODULE_REGISTRY.keys()),
        )

        all_findings: List[Finding] = []
        all_hosts: List[HostResult] = []

        for line in lines:
            sub_res = await self.scan(line, enabled_modules=enabled_modules, cvss_filter=cvss_filter)
            all_findings.extend(sub_res.findings)
            all_hosts.extend(sub_res.hosts)

        combined_result.hosts = all_hosts
        combined_result.findings = all_findings
        combined_result.completed_at = datetime.now(timezone.utc)
        combined_result.elapsed_seconds = (combined_result.completed_at - combined_result.started_at).total_seconds()
        combined_result.calculate_summary()
        return combined_result


# Alias for backward compatibility and clean branding
DetectIEngine = ThreatTrackEngine

