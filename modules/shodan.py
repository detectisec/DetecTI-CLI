"""Shodan.io Infrastructure Mapping and Vulnerability Collection Module."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from typing import Any, Dict, List, Optional, Set
from config import settings
from core.models import (
    Finding,
    FindingType,
    HostInfoData,
    PortData,
    VulnerabilityData,
)
from modules.base import BaseModule

logger = logging.getLogger("detecti.shodan")


class ShodanModule(BaseModule):
    """Refactored Shodan collector supporting host lookups, CIDR ranges, DNS, and search queries."""

    name: str = "shodan"
    description: str = "Shodan.io internet-wide scanner & asset intelligence"
    category: str = "recon"

    def __init__(
        self,
        client: Optional[AsyncHTTPClient] = None,
        progress_callback: Optional[Any] = None,
    ):
        super().__init__(client=client, progress_callback=progress_callback)
        self._auth_failed = False
        self._validated_result: Optional[tuple[bool, str]] = None

    def is_configured(self) -> bool:
        """Check if valid Shodan API key is set."""
        if self._auth_failed:
            return False
        from config import is_placeholder_key
        return bool(settings.shodan_api_key and not is_placeholder_key(settings.shodan_api_key))

    async def validate_credentials(self) -> bool:
        """Perform a fast pre-flight authentication verification check against Shodan API."""
        is_valid, _ = await self.validate_credentials_detailed()
        return is_valid

    async def validate_credentials_detailed(self, force: bool = False) -> tuple[bool, str]:
        """Perform a fast pre-flight authentication check returning validity and human-readable status."""
        if not force and self._validated_result is not None:
            return self._validated_result

        if not self.is_configured():
            return False, "Not Configured"
        url = "https://api.shodan.io/api-info"
        params = {"key": settings.shodan_api_key}
        try:
            resp = await self.http_client.get(
                url=url,
                params=params,
                timeout=4.0,
                max_retries=1,
                max_retry_delay=2.0,
                raise_for_status=False,
            )
            if resp.status_code == 200:
                res = (True, "Active & Valid")
            elif resp.status_code in (401, 403):
                self._auth_failed = True
                logger.debug("Shodan API key validation failed (HTTP 401/403).")
                res = (False, "Invalid Key (HTTP 401/403)")
            elif resp.status_code == 429:
                logger.warning("Shodan API rate limit reached during pre-flight check.")
                res = (False, "Rate Limited / Throttled (HTTP 429)")
            else:
                logger.debug(f"Shodan API key pre-check returned HTTP {resp.status_code}.")
                res = (False, f"API Error (HTTP {resp.status_code})")
        except Exception as exc:
            logger.debug(f"Shodan API key pre-check encountered network exception: {exc}")
            res = (False, f"Network / Timeout Error ({type(exc).__name__})")

        self._validated_result = res
        return res

    async def run(
        self,
        target: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Finding]:
        """Execute Shodan queries based on target input type."""
        if self._auth_failed or not self.is_configured():
            logger.warning("Shodan API key is not configured or invalid. Skipping Shodan module.")
            return []

        target = target.strip()
        findings: List[Finding] = []

        # 1. Target Cleaning and Normalization
        clean_target = target
        if clean_target.startswith("host:"):
            clean_target = clean_target[5:].strip()
        elif clean_target.startswith("domain:"):
            clean_target = clean_target[7:].strip()

        if clean_target.startswith("http://") or clean_target.startswith("https://"):
            clean_target = clean_target.split("//")[1].split("/")[0]
        if ":" in clean_target and " " not in clean_target and not clean_target.startswith("net:"):
            clean_target = clean_target.split(":")[0]
        if "/" in clean_target and not clean_target.startswith("net:"):
            try:
                ipaddress.ip_network(clean_target, strict=False)
            except ValueError:
                clean_target = clean_target.split("/")[0]

        # 2. CIDR Network Check (e.g. 192.168.1.0/24 or host:192.168.1.0/24)
        if "/" in clean_target:
            try:
                network = ipaddress.ip_network(clean_target, strict=False)
                # First attempt Shodan net: filter search to find all indexed hosts in subnet
                net_findings = await self.search_query(f"net:{clean_target}")
                if net_findings:
                    return net_findings

                # Fallback for small subnets (<= /28) if net query returned no results
                if network.num_addresses <= 16:
                    hosts = list(network.hosts())
                    host_tasks = [self.get_host_info(str(host_ip), context=context) for host_ip in hosts]
                    if host_tasks:
                        results = await asyncio.gather(*host_tasks, return_exceptions=True)
                        for res in results:
                            if isinstance(res, list):
                                findings.extend(res)
                return findings
            except ValueError:
                pass

        # 3. Direct IP Address Check
        try:
            ipaddress.ip_address(clean_target)
            return await self.get_host_info(clean_target, context=context)
        except ValueError:
            pass

        # 4. Domain & Subdomain Check (DNS domain info & hostname query)
        import tldextract
        ext = tldextract.extract(clean_target)
        if ext.domain and ext.suffix and " " not in clean_target:
            root_domain = ext.registered_domain or f"{ext.domain}.{ext.suffix}"
            dns_findings = await self.get_domain_info(root_domain)
            findings.extend(dns_findings)

            # If targeting a specific subdomain, query hostname in Shodan
            if clean_target != root_domain:
                try:
                    host_findings = await self.search_query(f"hostname:{clean_target}", max_pages=1)
                    findings.extend(host_findings)
                except Exception as exc:
                    logger.debug(f"Shodan hostname search error for {clean_target}: {exc}")

            return findings

        # 5. Search Query Check
        query = target[5:] if target.startswith("host:") else target
        return await self.search_query(query)

    async def get_host_info(self, ip: str, context: Optional[Dict[str, Any]] = None) -> List[Finding]:
        """Fetch host info and ports from Shodan for a specific IP."""
        url = f"https://api.shodan.io/shodan/host/{ip}"
        params = {"key": settings.shodan_api_key, "minify": "false"}

        try:
            resp = await self.http_client.get(url=url, params=params, timeout=20.0, raise_for_status=False)
            if resp.status_code == 200:
                data = resp.json()
            else:
                try:
                    err_payload = resp.json()
                    err_msg = err_payload.get("error") if isinstance(err_payload, dict) else str(err_payload)
                except Exception:
                    err_msg = resp.text.strip() or f"HTTP {resp.status_code}"

                log_entry = f"Shodan [{ip}]: {err_msg}"
                if resp.status_code == 404:
                    logger.info(log_entry)
                elif resp.status_code == 429:
                    logger.warning(log_entry)
                else:
                    logger.debug(log_entry)

                self.notify(f"[{ip}] Shodan: {err_msg}")
                if context is not None and "warnings" in context and isinstance(context["warnings"], list):
                    context["warnings"].append(log_entry)
                return []
        except Exception as exc:
            logger.debug(f"Shodan host query exception for {ip}: {exc}")
            return []

        if not data:
            return []

        findings: List[Finding] = []

        hostnames = data.get("hostnames", [])
        domains = data.get("domains", [])
        ports = data.get("ports", [])
        vulns = data.get("vulns", [])

        host_info = HostInfoData(
            ip=data.get("ip_str", ip),
            hostnames=hostnames,
            domains=domains,
            org=data.get("org"),
            isp=data.get("isp"),
            asn=data.get("asn"),
            os=data.get("os"),
            country_name=data.get("country_name"),
            country_code=data.get("country_code"),
            city=data.get("city"),
            region_code=data.get("region_code"),
            postal_code=data.get("postal_code"),
            latitude=data.get("latitude"),
            longitude=data.get("longitude"),
            ports=ports,
            vulns=vulns,
        )

        # 1. Host Info Finding
        findings.append(
            Finding(
                type=FindingType.HOST_INFO,
                target=ip,
                value=ip,
                source="Shodan",
                host_ip=ip,
                host_info=host_info,
                metadata={"host_data": {k: data.get(k) for k in ["org", "isp", "os", "country_name"]}},
            )
        )

        # 2. Port & Service Findings
        for item in data.get("data", []):
            port_num = item.get("port")
            if port_num is None:
                continue

            product = item.get("product")
            version = item.get("version")
            transport = item.get("transport", "tcp")
            is_ssl = "ssl" in item
            is_http = "http" in item or port_num in (80, 443, 8080, 8443)

            web_url = None
            if is_http:
                scheme = "https" if is_ssl or port_num in (443, 8443) else "http"
                web_url = f"{scheme}://{ip}:{port_num}"

            port_obj = PortData(
                port=port_num,
                transport=transport,
                service=item.get("_shodan", {}).get("module") or ("http" if is_http else None),
                product=product,
                version=version,
                banner=item.get("data", "").strip() if item.get("data") else None,
                url=web_url,
                ssl=is_ssl,
                sources=["Shodan"],
            )

            findings.append(
                Finding(
                    type=FindingType.OPEN_PORT,
                    target=ip,
                    value=f"{ip}:{port_num}",
                    source="Shodan",
                    host_ip=ip,
                    port_info=port_obj,
                    metadata={"transport": transport, "product": product, "version": version},
                )
            )

        # 3. Associated Domains & Hostnames
        for domain in domains:
            findings.append(
                Finding(
                    type=FindingType.ASSOCIATED_DOMAIN,
                    target=ip,
                    value=domain,
                    source="Shodan (Host Domains)",
                    host_ip=ip,
                )
            )
        for hname in hostnames:
            findings.append(
                Finding(
                    type=FindingType.SUBDOMAIN,
                    target=ip,
                    value=hname,
                    source="Shodan (Hostnames)",
                    host_ip=ip,
                )
            )

        # 4. Vulnerability (CVE) Findings
        for cve in vulns:
            findings.append(
                Finding(
                    type=FindingType.VULNERABILITY,
                    target=ip,
                    value=cve,
                    source="Shodan",
                    host_ip=ip,
                    vulnerability=VulnerabilityData(cve_id=cve),
                    metadata={"ip": ip},
                )
            )

        return findings

    async def get_domain_info(self, domain: str) -> List[Finding]:
        """Fetch DNS domain info and subdomains from Shodan."""
        clean_domain = domain.strip().lower()
        if clean_domain.startswith("http://") or clean_domain.startswith("https://"):
            clean_domain = clean_domain.split("//")[1].split("/")[0]
        if ":" in clean_domain:
            clean_domain = clean_domain.split(":")[0]
        if "/" in clean_domain:
            clean_domain = clean_domain.split("/")[0]

        import tldextract
        ext = tldextract.extract(clean_domain)
        search_domain = ext.registered_domain if (ext.domain and ext.suffix) else clean_domain

        url = f"https://api.shodan.io/dns/domain/{search_domain}"
        params = {"key": settings.shodan_api_key, "history": "true"}

        data = await self.http_client.get_json(url=url, params=params, timeout=20.0)
        if not data:
            return []

        findings: List[Finding] = []
        dns_records = data.get("data", [])

        for record in dns_records:
            sub = record.get("subdomain")
            rec_type = record.get("type")
            value = record.get("value")
            full_domain = f"{sub}.{domain}" if sub else domain

            findings.append(
                Finding(
                    type=FindingType.SUBDOMAIN,
                    target=domain,
                    value=full_domain,
                    source="Shodan DNS",
                    metadata={"dns_type": rec_type, "value": value},
                )
            )

            # If the record resolves to an IP address (A or AAAA), query host info
            if value and rec_type in ("A", "AAAA"):
                try:
                    ipaddress.ip_address(value)
                    host_findings = await self.get_host_info(value)
                    findings.extend(host_findings)
                except ValueError:
                    pass

        return findings

    async def search_query(self, query: str, max_pages: Optional[int] = None) -> List[Finding]:
        """Search Shodan using query syntax and resolve host dossiers for all matches across all pages."""
        findings: List[Finding] = []
        url = "https://api.shodan.io/shodan/host/search"
        page = 1
        seen_ips: Set[str] = set()

        while True:
            if max_pages and page > max_pages:
                break

            params = {
                "key": settings.shodan_api_key,
                "query": query,
                "page": page,
            }
            data = await self.http_client.get_json(url=url, params=params, timeout=25.0)
            if not data or not isinstance(data, dict):
                break

            matches = data.get("matches", [])
            if not matches:
                break

            page_ips = [m.get("ip_str") for m in matches if m.get("ip_str") and m.get("ip_str") not in seen_ips]
            for ip in page_ips:
                seen_ips.add(ip)

            if page_ips:
                host_tasks = [self.get_host_info(ip) for ip in page_ips]
                host_results = await asyncio.gather(*host_tasks, return_exceptions=True)
                for h_res in host_results:
                    if isinstance(h_res, list):
                        findings.extend(h_res)

            total = data.get("total", 0)
            if page * 100 >= total:
                break
            page += 1

        return findings
