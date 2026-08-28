"""Certificate Transparency (crt.sh) Subdomain Enumeration Module."""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Set
from config import settings
from core.models import Finding, FindingType
from modules.base import BaseModule

logger = logging.getLogger("detecti.crtsh")


class CrtshModule(BaseModule):
    """Enumerates subdomains using public Certificate Transparency logs via crt.sh."""

    name: str = "crtsh"
    description: str = "Certificate Transparency logs subdomain discovery"
    category: str = "recon"

    # Regex to validate valid domain/subdomain formats
    DOMAIN_REGEX = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )

    async def run(
        self,
        target: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Finding]:
        """Query crt.sh for domain certificates and extract unique subdomains."""
        # Clean target and extract registered root domain
        domain = target.strip().lower()
        if domain.startswith("http://") or domain.startswith("https://"):
            domain = domain.split("//")[1].split("/")[0]
        if ":" in domain:
            domain = domain.split(":")[0]
        if "/" in domain:
            domain = domain.split("/")[0]

        import tldextract
        ext = tldextract.extract(domain)
        search_domain = ext.registered_domain if (ext.domain and ext.suffix) else domain

        # crt.sh query format
        url = f"{settings.crtsh_api_url}/"
        params = {"q": f"%.{search_domain}", "output": "json"}

        findings: List[Finding] = []
        discovered_subdomains: Set[str] = set()

        try:
            data = await self.http_client.get_json(url=url, params=params, timeout=20.0)
            if not data or not isinstance(data, list):
                logger.debug(f"No certificate data returned from crt.sh for {domain}")
                return findings

            for entry in data:
                name_value = entry.get("name_value", "")
                if not name_value:
                    continue

                # An entry may contain multiple names separated by newlines
                names = name_value.split("\n")
                for name in names:
                    clean_name = name.strip().lower()
                    # Strip leading wildcard *.
                    if clean_name.startswith("*."):
                        clean_name = clean_name[2:]

                    if (
                        clean_name
                        and clean_name.endswith(domain)
                        and self.DOMAIN_REGEX.match(clean_name)
                    ):
                        discovered_subdomains.add(clean_name)

            for sub in sorted(discovered_subdomains):
                findings.append(
                    Finding(
                        type=FindingType.SUBDOMAIN,
                        target=domain,
                        value=sub,
                        source="crt.sh",
                        metadata={
                            "parent_domain": domain,
                            "is_apex": sub == domain,
                        },
                    )
                )

            logger.info(f"crt.sh discovered {len(findings)} unique subdomains for {domain}")

        except Exception as exc:
            logger.warning(f"Error querying crt.sh for {domain}: {exc}")

        return findings
