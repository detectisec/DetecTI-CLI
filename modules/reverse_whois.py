"""Reverse WHOIS and Organization Correlation Module."""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Set
from config import settings
from core.models import Finding, FindingType
from modules.base import BaseModule

logger = logging.getLogger("detecti.reverse_whois")


class ReverseWhoisModule(BaseModule):
    """Discovers correlated domains owned by the same organization or registrant.

    Employs a hybrid strategy:
    - Paid/Structured API: WhoisFreaks (if WHOISFREAKS_API_KEY configured)
    - Free Fallbacks: HackerTarget Reverse IP / WHOIS & RDAP queries
    """

    name: str = "reverse_whois"
    description: str = "Reverse WHOIS & Organization domain correlation"
    category: str = "osint"

    EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
    DOMAIN_REGEX = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )

    def is_configured(self) -> bool:
        """Check if WhoisFreaks paid API is configured (optional - free fallback available)."""
        from config import is_placeholder_key
        return bool(settings.whoisfreaks_api_key and not is_placeholder_key(settings.whoisfreaks_api_key))

    async def run(
        self,
        target: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Finding]:
        """Execute reverse WHOIS query based on target type (email, org, or domain/ip)."""
        target = target.strip()
        clean_target = target
        if clean_target.startswith("http://") or clean_target.startswith("https://"):
            clean_target = clean_target.split("//")[1].split("/")[0]
        if ":" in clean_target and " " not in clean_target:
            clean_target = clean_target.split(":")[0]
        if "/" in clean_target:
            clean_target = clean_target.split("/")[0]

        findings: List[Finding] = []

        if self.is_configured():
            logger.info("Executing structured Reverse WHOIS via WhoisFreaks API...")
            findings = await self._query_whoisfreaks(clean_target)
            if findings:
                return findings

        # Free fallback execution
        logger.info("Executing free Reverse WHOIS / HackerTarget discovery fallback...")
        findings = await self._query_free_fallbacks(clean_target)
        return findings

    async def _query_whoisfreaks(self, target: str) -> List[Finding]:
        """Query WhoisFreaks Reverse WHOIS API with complete multi-page pagination."""
        findings: List[Finding] = []
        seen_domains: Set[str] = set()
        url = settings.whoisfreaks_reverse_whois_url

        params: Dict[str, Any] = {
            "apiKey": settings.whoisfreaks_api_key,
            "format": "JSON",
        }

        if self.EMAIL_REGEX.match(target):
            params["email"] = target
            query_type = "email"
        elif self.DOMAIN_REGEX.match(target):
            params["domain"] = target
            query_type = "domain"
        else:
            params["org"] = target
            query_type = "org"

        page = 1
        while True:
            params["page"] = page
            try:
                data = await self.http_client.get_json(url=url, params=params, timeout=20.0)
                if not data or not isinstance(data, dict):
                    break

                domain_list = data.get("whois_domains", []) or data.get("domains", [])
                if not domain_list:
                    break

                for item in domain_list:
                    domain_name = item.get("domain_name") if isinstance(item, dict) else str(item)
                    if domain_name and self.DOMAIN_REGEX.match(domain_name):
                        clean_dom = domain_name.lower()
                        if clean_dom not in seen_domains:
                            seen_domains.add(clean_dom)
                            findings.append(
                                Finding(
                                    type=FindingType.ASSOCIATED_DOMAIN,
                                    target=target,
                                    value=clean_dom,
                                    source="WhoisFreaks (Reverse WHOIS)",
                                    metadata={
                                        "query_type": query_type,
                                        "provider": "WhoisFreaks",
                                    },
                                )
                            )

                total_pages = data.get("total_pages") or data.get("totalPages")
                if not total_pages or page >= int(total_pages):
                    break
                page += 1
            except Exception as exc:
                logger.warning(f"Error querying WhoisFreaks API page {page}: {exc}")
                break

        return findings

    async def _query_free_fallbacks(self, target: str) -> List[Finding]:
        """Free endpoints fallback: HackerTarget Reverse IP, WHOIS, and RDAP."""
        findings: List[Finding] = []
        discovered_domains: Set[str] = set()

        # 1. If target is an IP or Domain: HackerTarget Reverse IP lookup
        # (Skip if the target IP / domain resolves to a shared CDN/Anycast proxy like Cloudflare, Fastly, Akamai)
        skip_reverse_ip = False
        target_ip = None
        try:
            import ipaddress, socket
            # If target is already an IP
            try:
                ipaddress.ip_address(target)
                target_ip = target
            except ValueError:
                # If target is a domain, resolve its current IP
                try:
                    target_ip = socket.gethostbyname(target)
                except Exception:
                    pass

            if target_ip:
                ip_obj = ipaddress.ip_address(target_ip)
                # Known shared CDN/Anycast IP networks
                cdn_nets = [
                    ipaddress.ip_network("104.16.0.0/12"),
                    ipaddress.ip_network("172.64.0.0/13"),
                    ipaddress.ip_network("162.158.0.0/15"),
                    ipaddress.ip_network("198.41.128.0/17"),
                    ipaddress.ip_network("197.234.240.0/22"),
                    ipaddress.ip_network("188.114.96.0/20"),
                    ipaddress.ip_network("190.93.240.0/20"),
                    ipaddress.ip_network("108.162.192.0/18"),
                    ipaddress.ip_network("131.0.72.0/22"),
                    ipaddress.ip_network("141.101.64.0/18"),
                    ipaddress.ip_network("103.21.244.0/22"),
                    ipaddress.ip_network("103.22.200.0/22"),
                    ipaddress.ip_network("103.31.4.0/22"),
                    ipaddress.ip_network("173.245.48.0/20"),
                    ipaddress.ip_network("151.101.0.0/16"),   # Fastly
                    ipaddress.ip_network("199.232.0.0/16"),   # Fastly
                    ipaddress.ip_network("199.83.128.0/21"),  # Imperva
                    ipaddress.ip_network("198.143.32.0/19"),  # Imperva
                ]
                if any(ip_obj in net for net in cdn_nets):
                    skip_reverse_ip = True
                    logger.info(f"Target {target} ({target_ip}) resides on a shared CDN/Anycast proxy (Cloudflare/Fastly/Imperva). Skipping Reverse IP to prevent tenant noise.")
        except Exception as exc:
            logger.debug(f"CDN detection check error for {target}: {exc}")

        if not skip_reverse_ip:
            try:
                url = settings.hackertarget_reverse_ip_url
                params = {"q": target}
                resp = await self.http_client.get(url=url, params=params, timeout=15.0, raise_for_status=False)
                if resp.status_code == 200:
                    text = resp.text.strip()
                    if text and "API count exceeded" not in text and "No records" not in text and "error" not in text.lower():
                        for line in text.splitlines():
                            candidate = line.strip().lower()
                            if candidate and self.DOMAIN_REGEX.match(candidate):
                                discovered_domains.add(candidate)
            except Exception as exc:
                logger.debug(f"HackerTarget Reverse IP error for {target}: {exc}")

        # 2. If target is a Domain: Query WHOIS to extract organization and emails for context
        if self.DOMAIN_REGEX.match(target):
            try:
                whois_url = settings.hackertarget_whois_url
                resp = await self.http_client.get(url=whois_url, params={"q": target}, timeout=15.0, raise_for_status=False)
                if resp.status_code == 200:
                    text = resp.text
                    emails = set(self.EMAIL_REGEX.findall(text))
                    # Ignore common privacy guard emails
                    filtered_emails = [
                        e for e in emails
                        if not any(guard in e.lower() for guard in ["privacy", "whoisguard", "domainprotection", "contactprivacy", "superprivacy"])
                    ]
                    for em in filtered_emails:
                        logger.info(f"Identified registrant contact email: {em}")
            except Exception as exc:
                logger.debug(f"HackerTarget WHOIS error for {target}: {exc}")

        for dom in sorted(discovered_domains):
            findings.append(
                Finding(
                    type=FindingType.ASSOCIATED_DOMAIN,
                    target=target,
                    value=dom,
                    source="HackerTarget (Reverse WHOIS/IP)",
                    metadata={
                        "target": target,
                        "method": "free_fallback",
                    },
                )
            )

        return findings
