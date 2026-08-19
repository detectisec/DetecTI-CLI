"""Censys Platform API (v3) Asset and Host Intelligence Module."""

from __future__ import annotations

import base64
import ipaddress
import logging
import os
import time
import uuid
from typing import Any, Dict, List, Optional
import requests

from config import settings
from core.models import (
    Finding,
    FindingType,
    HostInfoData,
    PortData,
    VulnerabilityData,
)
from modules.base import BaseModule
from utils.http import AsyncHTTPClient, http_client

logger = logging.getLogger("detecti.censys")


def is_valid_uuid(val: Optional[str]) -> bool:
    """Check if a string represents a valid UUID (required by Censys for Organization ID)."""
    if not val or not isinstance(val, str):
        return False
    try:
        uuid.UUID(val.strip())
        return True
    except (ValueError, AttributeError):
        return False


class CensysAPIError(Exception):
    """Base exception for Censys Platform API errors."""
    pass


class CensysAuthError(CensysAPIError):
    """Exception for Authentication/Authorization errors (401/403)."""
    pass


class CensysRateLimitError(CensysAPIError):
    """Exception for Rate Limit exceeded (429)."""
    pass


class CensysQuotaExhaustedError(CensysAPIError):
    """Exception for API quota/balance exhausted (422 with insufficient balance)."""
    pass


class CensysPlatformClient:
    """Synchronous reference client for integration with Censys Platform API v3."""

    BASE_URL = "https://api.platform.censys.io/v3"

    def __init__(self, pat_token: Optional[str] = None, org_id: Optional[str] = None):
        self.pat_token = pat_token or settings.censys_pat_token or os.getenv("CENSYS_PAT_TOKEN")
        self.org_id = org_id or settings.censys_org_id or os.getenv("CENSYS_ORG_ID")

        if not self.pat_token:
            raise ValueError("O token PAT (CENSYS_PAT_TOKEN) é obrigatório para autenticação.")

        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.pat_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        if self.org_id and is_valid_uuid(self.org_id):
            self.session.headers.update({"X-Organization-ID": self.org_id.strip()})

    def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        max_retries: int = 3,
    ) -> Dict[str, Any]:
        """Execute HTTP request with exponential backoff and error handling."""
        url = f"{self.BASE_URL}{endpoint}"

        for attempt in range(max_retries):
            try:
                response = self.session.request(method, url, params=params, json=json_data)

                if response.status_code == 200:
                    return response.json()
                elif response.status_code in (401, 403):
                    raise CensysAuthError(f"Erro de Autenticação/Permissão [{response.status_code}]: {response.text}")
                elif response.status_code == 429:
                    if attempt < max_retries - 1:
                        time.sleep(2 ** attempt)
                        continue
                    raise CensysRateLimitError("Limite de taxa excedido (429).")
                elif response.status_code == 422:
                    # Check if it's a quota exhaustion error
                    try:
                        error_data = response.json()
                        if isinstance(error_data, dict) and "errors" in error_data:
                            for error in error_data.get("errors", []):
                                if isinstance(error, dict) and "insufficient balance" in error.get("message", "").lower():
                                    raise CensysQuotaExhaustedError("API quota/balance exhausted")
                    except:
                        pass  # If we can't parse the error, treat it as a regular validation error
                    
                    raise CensysAPIError(f"Erro de validação ou query CenQL (422): {response.text}")
                else:
                    response.raise_for_status()
            except requests.RequestException as exc:
                if attempt >= max_retries - 1:
                    raise CensysAPIError(f"Falha na requisição Censys após múltiplas tentativas: {exc}")
                time.sleep(2 ** attempt)

        raise CensysAPIError("Falha na requisição após múltiplas tentativas.")

    def get_host(self, ip: str) -> Dict[str, Any]:
        """Obtém detalhes de um host específico por IP via Censys Platform API v3."""
        return self._request("GET", f"/global/asset/host/{ip}")

    def search_query(self, query: str, page_size: int = 100, cursor: Optional[str] = None) -> Dict[str, Any]:
        """Executa uma busca unificada usando a linguagem CenQL."""
        payload: Dict[str, Any] = {"query": query, "page_size": page_size}
        if cursor:
            payload["cursor"] = cursor
        return self._request("POST", "/global/search/query", json_data=payload)

    def aggregate_search(self, query: str, field: str, num_buckets: int = 10) -> Dict[str, Any]:
        """Calcula estatísticas agregadas por campos específicos."""
        payload = {"query": query, "field": field, "num_buckets": num_buckets}
        return self._request("POST", "/global/search/aggregate", json_data=payload)

    def get_certificate(self, fingerprint: str) -> Dict[str, Any]:
        """Retorna informações detalhadas de um certificado pelo fingerprint SHA-256."""
        return self._request("GET", f"/global/asset/certificate/{fingerprint}")

    def convert_legacy_query(self, legacy_query: str) -> Dict[str, Any]:
        """Converte consultas da API Legada (v1/v2) para a sintaxe CenQL."""
        payload = {"query": legacy_query}
        return self._request("POST", "/global/search/convert", json_data=payload)


class CensysModule(BaseModule):
    """Censys Platform API (v3) asynchronous collector supporting CenQL search, host asset lookups, and CIDR ranges."""

    name: str = "censys"
    description: str = "Censys Platform API v3 internet-wide asset & host scanner"
    category: str = "recon"

    def __init__(
        self,
        client: Optional[AsyncHTTPClient] = None,
        pat_token: Optional[str] = None,
        org_id: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        super().__init__(client=client)
        self.pat_token = pat_token or settings.censys_pat_token or os.getenv("CENSYS_PAT_TOKEN")
        self.org_id = org_id or settings.censys_org_id or os.getenv("CENSYS_ORG_ID")
        self.base_url = (base_url or settings.censys_platform_api_url or "https://api.platform.censys.io/v3").rstrip("/")
        self._quota_exhausted = False  # Flag to skip further API calls when quota is exhausted

    def is_configured(self) -> bool:
        """Check if Censys API credentials (PAT token or legacy ID/Secret) are set."""
        has_pat = bool(self.pat_token or settings.censys_pat_token or os.getenv("CENSYS_PAT_TOKEN"))
        has_legacy = bool(settings.censys_api_id and settings.censys_api_secret)
        return has_pat or has_legacy

    def _get_auth_headers(self, accept_header: str = "application/json") -> Dict[str, str]:
        """Generate Platform API v3 Bearer token (or legacy fallback) and Organization headers."""
        headers: Dict[str, str] = {
            "Accept": accept_header,
            "Content-Type": "application/json",
        }

        pat = self.pat_token or settings.censys_pat_token or os.getenv("CENSYS_PAT_TOKEN")
        if pat:
            headers["Authorization"] = f"Bearer {pat}"
        elif settings.censys_api_id and settings.censys_api_secret:
            auth_bytes = f"{settings.censys_api_id}:{settings.censys_api_secret}".encode("utf-8")
            b64_auth = base64.b64encode(auth_bytes).decode("utf-8")
            headers["Authorization"] = f"Basic {b64_auth}"

        org_id = self.org_id or settings.censys_org_id or os.getenv("CENSYS_ORG_ID")
        if org_id and is_valid_uuid(org_id):
            headers["X-Organization-ID"] = org_id.strip()
        elif org_id:
            logger.debug(
                f"Ignoring CENSYS_ORG_ID='{org_id}' because it is not a valid UUID. "
                f"Free accounts operate without Organization ID."
            )

        return headers

    async def run(
        self,
        target: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Finding]:
        """Execute Censys v3 Platform queries based on target input type."""
        if not self.is_configured():
            logger.warning("Censys API credentials are not configured. Skipping Censys module.")
            return []

        # Skip if quota was previously exhausted
        if self._quota_exhausted:
            logger.info("Censys API quota exhausted. Skipping further Censys queries.")
            return []

        target = target.strip()

        try:
            # Clean prefix markers if present
            clean_target = target
            if clean_target.startswith("host:"):
                clean_target = clean_target[5:]
            elif clean_target.startswith("domain:"):
                clean_target = clean_target[7:]

            # 1. CIDR Network Check (e.g., 192.168.1.0/24) -> CenQL ip: 192.168.1.0/24
            if "/" in clean_target:
                try:
                    ipaddress.ip_network(clean_target, strict=False)
                    return await self.search_query(f"ip: {clean_target}")
                except ValueError:
                    pass

            # 2. Direct IP Address Check -> GET /v3/global/asset/host/{ip}
            try:
                ipaddress.ip_address(clean_target)
                return await self.get_host_info(clean_target)
            except ValueError:
                pass

            # 3. Domain Check -> CenQL names: example.com
            if target.startswith("domain:") or ("." in target and " " not in target and ":" not in target):
                domain_name = clean_target
                return await self.search_query(f"names: {domain_name}")

            # 4. Search Query / CenQL Query
            query = clean_target
            return await self.search_query(query)
            
        except CensysQuotaExhaustedError as e:
            logger.warning(f"Censys API quota exhausted for target {target}")
            print(f"⚠️  Censys API quota/balance exhausted. Skipping further Censys queries.")
            self._quota_exhausted = True  # Set flag to skip future calls
            return []
        except CensysRateLimitError as e:
            logger.warning(f"Censys API rate limit exceeded for target {target}")
            print(f"⚠️  Censys API rate limit exceeded. Please wait before making more requests or upgrade your plan.")
            return []
        except CensysAuthError as e:
            logger.error(f"Censys authentication error for target {target}")
            print(f"❌ Censys authentication failed. Please check your API credentials.")
            return []
        except CensysAPIError as e:
            logger.error(f"Censys API error for target {target}: {e}")
            print(f"⚠️  Censys API error: {e}")
            return []
        except Exception as e:
            logger.error(f"Censys module error for target {target}: {e}")
            return []

    async def get_host_info(self, ip: str) -> List[Finding]:
        """Fetch complete host dossier and open services from Censys Platform API v3."""
        url = f"{self.base_url}/global/asset/host/{ip}"
        headers = self._get_auth_headers(accept_header="application/vnd.censys.api.v3.host.v1+json")

        try:
            resp = await self.http_client.get(url=url, headers=headers, timeout=20.0, raise_for_status=False)
            if resp.status_code == 200:
                data = resp.json()
            elif resp.status_code == 404:
                logger.debug(f"Host {ip} not found in Censys Platform.")
                return []
            elif resp.status_code in (401, 403):
                logger.error(f"Censys Authentication/Permission error ({resp.status_code}): {resp.text}")
                raise CensysAuthError(f"Authentication failed for IP {ip}: HTTP {resp.status_code}")
            elif resp.status_code == 422:
                # Check if it's a quota exhaustion error
                try:
                    error_data = resp.json()
                    if isinstance(error_data, dict) and "errors" in error_data:
                        for error in error_data.get("errors", []):
                            if isinstance(error, dict) and "insufficient balance" in error.get("message", "").lower():
                                logger.warning(f"Censys API quota exhausted for host {ip}")
                                raise CensysQuotaExhaustedError(f"API quota exhausted for IP {ip}")
                except:
                    pass  # If we can't parse the error, treat it as a regular validation error
                
                logger.error(f"Censys validation error (422) for host {ip}: {resp.text}")
                raise CensysAPIError(f"Validation error for IP {ip}: {resp.text}")
            elif resp.status_code == 429:
                logger.warning(f"Censys Rate limit exceeded for host lookup: {ip}")
                raise CensysRateLimitError(f"Rate limit exceeded for IP {ip}")
            else:
                logger.warning(f"Censys API returned HTTP {resp.status_code} for host {ip}")
                raise CensysAPIError(f"API error for IP {ip}: HTTP {resp.status_code}")
        except (CensysQuotaExhaustedError, CensysRateLimitError, CensysAuthError, CensysAPIError):
            # Re-raise our custom exceptions
            raise
        except Exception as exc:
            logger.warning(f"Failed to fetch Censys host info for {ip}: {exc}")
            raise CensysAPIError(f"Network error for IP {ip}: {exc}")

        if not data or not isinstance(data, dict):
            return []

        return self._parse_host_result(ip, data)

    def _parse_host_result(self, ip: str, result_data: Dict[str, Any]) -> List[Finding]:
        """Parse structured host result from Censys Platform API v3 into standard Finding objects."""
        findings: List[Finding] = []

        # Unpack result / resource wrappers if present
        if isinstance(result_data, dict):
            if "result" in result_data and isinstance(result_data["result"], dict):
                result_data = result_data["result"]
            if "resource" in result_data and isinstance(result_data["resource"], dict):
                result_data = result_data["resource"]

        # Location details
        location = result_data.get("location", {})
        country_name = location.get("country") or location.get("country_name")
        country_code = location.get("country_code")
        city = location.get("city")
        region_code = location.get("province") or location.get("region_code")

        # Autonomous System
        as_info = result_data.get("autonomous_system", {})
        asn_num = as_info.get("asn")
        asn_str = f"AS{asn_num}" if asn_num else None
        org = as_info.get("name") or as_info.get("description")
        isp = as_info.get("description") or as_info.get("name")

        # Operating System
        os_info = result_data.get("operating_system", {})
        os_name = os_info.get("product") or os_info.get("uniform_resource_identifier")
        if not os_name and os_info.get("vendor"):
            os_name = f"{os_info.get('vendor')} {os_info.get('version', '')}".strip()

        # DNS Names & Hostnames
        dns_info = result_data.get("dns", {})
        dns_names: List[str] = dns_info.get("names", []) if isinstance(dns_info.get("names"), list) else []
        reverse_dns = dns_info.get("reverse_dns", {})
        rev_names: List[str] = []
        if isinstance(reverse_dns, dict):
            rev_names = reverse_dns.get("names", []) if isinstance(reverse_dns.get("names"), list) else []
        elif isinstance(reverse_dns, list):
            rev_names = reverse_dns

        hostnames: List[str] = list(set(dns_names + rev_names))
        domains: List[str] = []

        for h in hostnames:
            parts = h.split(".")
            if len(parts) >= 2:
                base_dom = ".".join(parts[-2:])
                if base_dom not in domains:
                    domains.append(base_dom)

        services = result_data.get("services", [])
        port_numbers: List[int] = []
        identified_cves: List[str] = []

        # 1. Parse Open Ports & Services
        for svc in services:
            if not isinstance(svc, dict):
                continue

            port_num = svc.get("port")
            if port_num is None:
                continue

            port_numbers.append(port_num)
            transport = (svc.get("transport_protocol") or "tcp").lower()

            # Software / Product details
            software_list = svc.get("software", [])
            product = None
            version = None
            if software_list and isinstance(software_list, list) and len(software_list) > 0:
                sw_item = software_list[0]
                if isinstance(sw_item, dict):
                    product = sw_item.get("product") or sw_item.get("vendor")
                    version = sw_item.get("version")

            # Endpoints & HTTP banners / titles / server headers
            endpoints = svc.get("endpoints", [])
            html_titles: List[str] = []
            server_headers: List[str] = []
            cert_names: List[str] = []

            if isinstance(endpoints, list):
                for ep in endpoints:
                    if not isinstance(ep, dict):
                        continue
                    http_info = ep.get("http", {})
                    if isinstance(http_info, dict):
                        t = http_info.get("html_title")
                        if t:
                            html_titles.append(str(t).strip())
                        srv_list = http_info.get("headers", {}).get("Server", {}).get("headers", [])
                        if isinstance(srv_list, list):
                            server_headers.extend(srv_list)
                    tls_info = ep.get("tls", {})
                    if isinstance(tls_info, dict):
                        c_names = tls_info.get("certificate", {}).get("names", [])
                        if isinstance(c_names, list):
                            cert_names.extend(c_names)

            # Direct TLS certificates
            direct_tls = svc.get("tls", {})
            if isinstance(direct_tls, dict):
                c_names = direct_tls.get("certificate", {}).get("names", [])
                if isinstance(c_names, list):
                    cert_names.extend(c_names)

            # Direct HTTP banner/title
            direct_http = svc.get("http", {})
            if isinstance(direct_http, dict):
                direct_title = direct_http.get("response", {}).get("html_title") or direct_http.get("html_title")
                if direct_title:
                    html_titles.append(str(direct_title).strip())

            # Banner selection
            banner_text = svc.get("banner")
            if not banner_text and html_titles:
                banner_text = html_titles[0]
            elif not banner_text and server_headers:
                banner_text = server_headers[0]

            # Service name heuristic
            service_name = svc.get("service_name") or svc.get("extended_service_name")
            if not service_name or service_name == "unknown":
                if product:
                    service_name = product.upper()
                elif html_titles or server_headers or port_num in (80, 8080, 3000, 8000, 8888):
                    service_name = "HTTP"
                elif cert_names or port_num in (443, 8443):
                    service_name = "HTTPS"
                elif port_num == 22:
                    service_name = "SSH"
                elif port_num == 21:
                    service_name = "FTP"
                elif port_num == 500:
                    service_name = "IKE"
                elif port_num == 1701:
                    service_name = "L2TP"
                elif port_num == 1723:
                    service_name = "PPTP"
                elif port_num == 8291:
                    service_name = "Winbox"
                elif port_num == 2000:
                    service_name = "Bandwidth-Test"
                else:
                    service_name = "unknown"

            # Web URL
            is_http = (
                service_name.lower() in ("http", "https")
                or port_num in (80, 443, 3000, 8080, 8443)
                or bool(html_titles or server_headers)
            )
            is_ssl = (
                "tls" in svc
                or service_name.lower() == "https"
                or port_num in (443, 8443)
                or bool(cert_names)
            )

            web_url = None
            if is_http:
                scheme = "https" if is_ssl else "http"
                web_url = f"{scheme}://{ip}:{port_num}"

            # Certificate Names (Subdomains / Domains discovery)
            for cname in cert_names:
                clean_cname = cname.lstrip("*.").lower()
                if clean_cname and clean_cname not in hostnames:
                    hostnames.append(clean_cname)
                parts = clean_cname.split(".")
                if len(parts) >= 2:
                    base_dom = ".".join(parts[-2:])
                    if base_dom not in domains:
                        domains.append(base_dom)

            port_obj = PortData(
                port=port_num,
                transport=transport,
                service=service_name,
                product=product,
                version=version,
                banner=str(banner_text).strip() if banner_text else None,
                url=web_url,
                ssl=is_ssl,
                sources=["Censys"],
            )

            findings.append(
                Finding(
                    type=FindingType.OPEN_PORT,
                    target=ip,
                    value=f"{ip}:{port_num}",
                    source="Censys Platform v3",
                    host_ip=ip,
                    port_info=port_obj,
                    metadata={
                        "transport": transport,
                        "service": service_name,
                        "product": product,
                        "version": version,
                        "server": server_headers[0] if server_headers else None,
                        "title": html_titles[0] if html_titles else None,
                    },
                )
            )

            # Check for service vulnerabilities
            for v in svc.get("vulnerabilities", []):
                cve_id = v if isinstance(v, str) else (v.get("cve") or v.get("cve_id") or v.get("id"))
                if cve_id and isinstance(cve_id, str) and cve_id.upper().startswith("CVE-"):
                    identified_cves.append(cve_id.upper())

        # Check for host-level vulnerabilities
        for v in result_data.get("vulnerabilities", []):
            cve_id = v if isinstance(v, str) else (v.get("cve") or v.get("cve_id") or v.get("id"))
            if cve_id and isinstance(cve_id, str) and cve_id.upper().startswith("CVE-"):
                identified_cves.append(cve_id.upper())

        host_info = HostInfoData(
            ip=ip,
            hostnames=sorted(list(set(hostnames))),
            domains=sorted(list(set(domains))),
            org=org,
            isp=isp,
            asn=asn_str,
            os=os_name,
            country_name=country_name,
            country_code=country_code,
            city=city,
            region_code=region_code,
            ports=sorted(list(set(port_numbers))),
            vulns=sorted(list(set(identified_cves))),
        )

        # 2. Host Info Finding
        findings.append(
            Finding(
                type=FindingType.HOST_INFO,
                target=ip,
                value=ip,
                source="Censys Platform v3",
                host_ip=ip,
                host_info=host_info,
                metadata={"provider": "Censys", "location": location, "autonomous_system": as_info},
            )
        )

        # 3. Associated Domains & Hostnames Findings
        for domain in sorted(list(set(domains))):
            findings.append(
                Finding(
                    type=FindingType.ASSOCIATED_DOMAIN,
                    target=ip,
                    value=domain,
                    source="Censys Platform v3 (Host Domains)",
                    host_ip=ip,
                )
            )
        for hname in sorted(list(set(hostnames))):
            findings.append(
                Finding(
                    type=FindingType.SUBDOMAIN,
                    target=ip,
                    value=hname,
                    source="Censys Platform v3 (DNS/Certs)",
                    host_ip=ip,
                )
            )

        # 4. Vulnerabilities Findings
        for cve in sorted(list(set(identified_cves))):
            findings.append(
                Finding(
                    type=FindingType.VULNERABILITY,
                    target=ip,
                    value=cve,
                    source="Censys Platform v3",
                    host_ip=ip,
                    vulnerability=VulnerabilityData(cve_id=cve),
                    metadata={"ip": ip},
                )
            )

        return findings

    async def search_query(
        self,
        query: str,
        page_size: int = 100,
        max_pages: Optional[int] = None,
    ) -> List[Finding]:
        """Execute CenQL unified search via Censys Platform API v3 across all pages (POST /v3/global/search/query)."""
        findings: List[Finding] = []
        url = f"{self.base_url}/global/search/query"
        headers = self._get_auth_headers()
        cursor: Optional[str] = None
        page_count = 0

        while True:
            if max_pages is not None and page_count >= max_pages:
                break
            page_count += 1

            payload: Dict[str, Any] = {
                "query": query,
                "page_size": page_size,
            }
            if cursor:
                payload["cursor"] = cursor

            try:
                resp = await self.http_client.post(
                    url=url,
                    headers=headers,
                    json=payload,
                    timeout=25.0,
                    raise_for_status=False,
                )

                if resp.status_code == 200:
                    data = resp.json()
                elif resp.status_code == 403:
                    err_msg = resp.text
                    if "organization ID for API access" in err_msg or "Free users" in err_msg:
                        logger.info(
                            "Censys CenQL search queries require an Organization ID / API Access tier. "
                            "Direct IP host lookups are supported on Free tier."
                        )
                    else:
                        logger.error(f"Censys Auth Error (403): {err_msg}")
                        raise CensysAuthError(f"Authentication failed for query '{query}': {err_msg}")
                    break
                elif resp.status_code == 401:
                    logger.error(f"Censys Auth Error (401): {resp.text}")
                    raise CensysAuthError(f"Authentication failed for query '{query}': HTTP 401")
                elif resp.status_code == 422:
                    # Check if it's a quota exhaustion error
                    try:
                        error_data = resp.json()
                        if isinstance(error_data, dict) and "errors" in error_data:
                            for error in error_data.get("errors", []):
                                if isinstance(error, dict) and "insufficient balance" in error.get("message", "").lower():
                                    logger.warning(f"Censys API quota exhausted for query '{query}'")
                                    raise CensysQuotaExhaustedError(f"API quota exhausted for query '{query}'")
                    except:
                        pass  # If we can't parse the error, treat it as a regular validation error
                    
                    logger.error(f"Censys CenQL Validation Error (422): {resp.text}")
                    raise CensysAPIError(f"Query validation error for '{query}': {resp.text}")
                elif resp.status_code == 429:
                    logger.warning("Censys Rate limit exceeded during search query.")
                    raise CensysRateLimitError(f"Rate limit exceeded for query '{query}'")
                else:
                    logger.warning(f"Censys search query returned HTTP {resp.status_code}: {resp.text}")
                    raise CensysAPIError(f"API error for query '{query}': HTTP {resp.status_code}")
            except (CensysQuotaExhaustedError, CensysRateLimitError, CensysAuthError, CensysAPIError):
                # Re-raise our custom exceptions
                raise
            except Exception as exc:
                logger.warning(f"Error executing Censys search query '{query}': {exc}")
                raise CensysAPIError(f"Network error for query '{query}': {exc}")

            if not data or not isinstance(data, dict):
                break

            result_data = data.get("result", {})
            hits = result_data.get("hits", [])
            if not hits:
                break

            for hit in hits:
                ip_str = hit.get("ip")
                if not ip_str:
                    continue

                if "services" in hit and hit.get("services"):
                    host_findings = self._parse_host_result(ip_str, hit)
                else:
                    host_findings = await self.get_host_info(ip_str)

                findings.extend(host_findings)

            links = result_data.get("links", {})
            cursor = links.get("next") or result_data.get("cursor")
            if not cursor:
                break

        return findings

    async def aggregate_search(
        self,
        query: str,
        field: str,
        num_buckets: int = 10,
    ) -> Dict[str, Any]:
        """Aggregate search results across global assets (POST /v3/global/search/aggregate)."""
        url = f"{self.base_url}/global/search/aggregate"
        headers = self._get_auth_headers()
        payload = {
            "query": query,
            "field": field,
            "num_buckets": num_buckets,
        }
        res = await self.http_client.post_json(url=url, headers=headers, json=payload, timeout=20.0)
        return res if isinstance(res, dict) else {}

    async def get_certificate(self, fingerprint: str) -> Dict[str, Any]:
        """Fetch SSL/TLS certificate details by SHA-256 fingerprint (GET /v3/global/asset/certificate/{fingerprint})."""
        url = f"{self.base_url}/global/asset/certificate/{fingerprint}"
        headers = self._get_auth_headers()
        res = await self.http_client.get_json(url=url, headers=headers, timeout=20.0)
        return res if isinstance(res, dict) else {}

    def convert_legacy_query(self, legacy_query: str) -> Dict[str, Any]:
        """Convert legacy search query syntax (v1/v2) to modern CenQL (POST /v3/global/search/convert)."""
        client = CensysPlatformClient(pat_token=self.pat_token, org_id=self.org_id)
        return client.convert_legacy_query(legacy_query)
