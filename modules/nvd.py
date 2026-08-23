"""NVD (National Vulnerability Database) + EPSS + CISA KEV Intelligence Module."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional, Set
from config import settings
from core.models import (
    CISAKEVData,
    EPSSData,
    Finding,
    FindingType,
    SeverityLevel,
    VulnerabilityData,
)
from modules.base import BaseModule

logger = logging.getLogger("detecti.nvd")

CWE_NAMES: Dict[str, str] = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-74": "Injection",
    "CWE-77": "Command Injection",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-119": "Memory Buffer Restriction Flaw",
    "CWE-120": "Classic Buffer Overflow",
    "CWE-121": "Stack-based Buffer Overflow",
    "CWE-122": "Heap-based Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-134": "Use of Externally-Controlled Format String",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-209": "Error Message Information Leak",
    "CWE-250": "Execution with Unnecessary Privileges",
    "CWE-264": "Permissions, Privileges, and Access Controls",
    "CWE-269": "Improper Privilege Management",
    "CWE-276": "Incorrect Default Permissions",
    "CWE-284": "Improper Access Control",
    "CWE-287": "Improper Authentication",
    "CWE-290": "Authentication Bypass by Spoofing",
    "CWE-295": "Improper Certificate Validation",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-307": "Improper Restriction of Excessive Auth Attempts",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-312": "Cleartext Storage of Sensitive Information",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-362": "Race Condition",
    "CWE-384": "Session Fixation",
    "CWE-400": "Uncontrolled Resource Consumption (DoS)",
    "CWE-415": "Double Free",
    "CWE-416": "Use After Free",
    "CWE-426": "Untrusted Search Path",
    "CWE-434": "Unrestricted File Upload",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-521": "Weak Password Requirements",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-532": "Insertion of Sensitive Information into Log File",
    "CWE-601": "Open Redirect",
    "CWE-611": "XML External Entity Reference (XXE)",
    "CWE-613": "Insufficient Session Expiration",
    "CWE-617": "Reachable Assertion",
    "CWE-640": "Weak Password Recovery Mechanism",
    "CWE-668": "Exposure of Resource to Wrong Sphere",
    "CWE-732": "Incorrect Permission Assignment for Critical Resource",
    "CWE-770": "Allocation of Resources Without Limits or Throttling",
    "CWE-787": "Out-of-bounds Write",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-829": "Inclusion of Functionality from Untrusted Sphere",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-917": "Expression Language Injection",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-922": "Insecure Storage of Sensitive Information",
    "CWE-1021": "Improper Restriction of UI Layers ('Clickjacking')",
    "CWE-1188": "Insecure Default Initialization of Resource",
    "CWE-1236": "Formula Elements in CSV Injection",
    "CWE-1321": "Prototype Pollution",
    "NVD-CWE-noinfo": "Insufficient Information",
    "NVD-CWE-Other": "Other Weakness",
}


class NVDModule(BaseModule):
    """Vulnerability enrichment module combining NVD 2.0, FIRST EPSS, and CISA KEV."""

    name: str = "nvd"
    description: str = "NVD CVSS severity, EPSS probability, and CISA KEV catalog enrichment"
    category: str = "vuln"

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._cisa_kev_cache: Optional[Dict[str, Dict[str, Any]]] = None
        self._cisa_lock = asyncio.Lock()

    def is_configured(self) -> bool:
        """Check if NVD custom API key is configured (optional, public rate limit fallback)."""
        from config import is_placeholder_key
        return bool(settings.nvd_api_key and not is_placeholder_key(settings.nvd_api_key))

    async def run(
        self,
        target: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Finding]:
        """Enrich a CVE or list of CVEs."""
        target = target.strip()
        cves_to_enrich: Set[str] = set()

        if target.upper().startswith("CVE-"):
            cves_to_enrich.add(target.upper())

        # Check context for CVEs discovered by previous modules (e.g. Shodan)
        if context and "cves" in context:
            for c in context["cves"]:
                if isinstance(c, str) and c.upper().startswith("CVE-"):
                    cves_to_enrich.add(c.upper())

        if not cves_to_enrich:
            logger.debug("No CVEs provided to NVD module for enrichment.")
            return []

        # Ensure CISA KEV is loaded into cache
        await self._ensure_cisa_kev_loaded()

        findings: List[Finding] = []
        for cve_id in sorted(cves_to_enrich):
            vuln_data = await self.enrich_cve(cve_id)
            if vuln_data:
                findings.append(
                    Finding(
                        type=FindingType.VULNERABILITY,
                        target=target,
                        value=cve_id,
                        source="NVD+EPSS+CISA",
                        vulnerability=vuln_data,
                    )
                )

        return findings

    async def _ensure_cisa_kev_loaded(self) -> None:
        """Fetch and index CISA KEV catalog once into memory."""
        if self._cisa_kev_cache is not None:
            return

        async with self._cisa_lock:
            if self._cisa_kev_cache is not None:
                return

            self._cisa_kev_cache = {}
            try:
                data = await self.http_client.get_json(url=settings.cisa_kev_url, timeout=20.0)
                if data and "vulnerabilities" in data:
                    for item in data["vulnerabilities"]:
                        cve = item.get("cveID", "").upper()
                        if cve:
                            self._cisa_kev_cache[cve] = item
                    logger.info(f"Loaded {len(self._cisa_kev_cache)} entries from CISA KEV catalog.")
            except Exception as exc:
                logger.warning(f"Failed to fetch CISA KEV catalog: {exc}")

    async def get_epss_score(self, cve_id: str) -> Optional[EPSSData]:
        """Fetch EPSS probability score and percentile from FIRST.org API."""
        url = settings.epss_api_url
        params = {"cve": cve_id}

        try:
            data = await self.http_client.get_json(url=url, params=params, timeout=10.0)
            if data and "data" in data and len(data["data"]) > 0:
                item = data["data"][0]
                return EPSSData(
                    epss_score=float(item.get("epss", 0.0)),
                    epss_percentile=float(item.get("percentile", 0.0)),
                    date=item.get("date"),
                )
        except Exception as exc:
            logger.debug(f"Error fetching EPSS for {cve_id}: {exc}")
        return None

    def get_cisa_kev_data(self, cve_id: str) -> Optional[CISAKEVData]:
        """Cross-reference CVE ID against the loaded CISA KEV catalog."""
        if not self._cisa_kev_cache or cve_id not in self._cisa_kev_cache:
            return None

        entry = self._cisa_kev_cache[cve_id]
        return CISAKEVData(
            in_cisa_kev=True,
            vendor_project=entry.get("vendorProject"),
            product=entry.get("product"),
            vulnerability_name=entry.get("vulnerabilityName"),
            date_added=entry.get("dateAdded"),
            due_date=entry.get("dueDate"),
            required_action=entry.get("requiredAction"),
            known_ransomware_campaign_use=entry.get("knownRansomwareCampaignUse"),
            notes=entry.get("notes"),
        )

    async def enrich_cve(self, cve_id: str) -> VulnerabilityData:
        """Fetch NVD CVSS details and combine with EPSS & CISA KEV."""
        # Ensure CISA KEV catalog is available in cache
        await self._ensure_cisa_kev_loaded()

        # Query NVD API 2.0
        nvd_url = settings.nvd_api_url
        headers: Dict[str, str] = {}
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key

        params = {"cveId": cve_id}
        nvd_data = await self.http_client.get_json(url=nvd_url, headers=headers, params=params, timeout=20.0)

        cvss_score: Optional[float] = None
        cvss_version: Optional[str] = None
        cvss_severity = SeverityLevel.UNKNOWN
        description: Optional[str] = None
        cwe_id: Optional[str] = None
        cwe_name: Optional[str] = None
        references: List[str] = []

        if nvd_data and "vulnerabilities" in nvd_data and len(nvd_data["vulnerabilities"]) > 0:
            cve_entry = nvd_data["vulnerabilities"][0].get("cve", {})

            # Descriptions
            for d in cve_entry.get("descriptions", []):
                if d.get("lang") == "en":
                    description = d.get("value")
                    break

            # References
            for ref in cve_entry.get("references", []):
                ref_url = ref.get("url")
                if ref_url:
                    references.append(ref_url)

            # Weaknesses (CWE)
            cwe_ids: List[str] = []
            cwe_names_list: List[str] = []
            for w in cve_entry.get("weaknesses", []):
                for d in w.get("description", []):
                    val = d.get("value")
                    if val and val not in cwe_ids:
                        cwe_ids.append(val)
                        val_upper = val.upper()
                        resolved_name = CWE_NAMES.get(val, CWE_NAMES.get(val_upper, val))
                        if resolved_name not in cwe_names_list:
                            cwe_names_list.append(resolved_name)

            if cwe_ids:
                cwe_id = ", ".join(cwe_ids)
            if cwe_names_list:
                cwe_name = ", ".join(cwe_names_list)

            # CVSS Metrics (Prioritize v3.1, then v3.0, then v2.0)
            metrics = cve_entry.get("metrics", {})
            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                primary_metric = metrics["cvssMetricV31"][0].get("cvssData", {})
                cvss_score = float(primary_metric.get("baseScore", 0.0))
                cvss_version = "3.1"
                sev_raw = primary_metric.get("baseSeverity", "UNKNOWN").upper()
                cvss_severity = SeverityLevel(sev_raw) if sev_raw in SeverityLevel.__members__ else SeverityLevel.UNKNOWN
            elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                primary_metric = metrics["cvssMetricV30"][0].get("cvssData", {})
                cvss_score = float(primary_metric.get("baseScore", 0.0))
                cvss_version = "3.0"
                sev_raw = primary_metric.get("baseSeverity", "UNKNOWN").upper()
                cvss_severity = SeverityLevel(sev_raw) if sev_raw in SeverityLevel.__members__ else SeverityLevel.UNKNOWN
            elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                primary_metric = metrics["cvssMetricV2"][0]
                cvss_score = float(primary_metric.get("cvssData", {}).get("baseScore", 0.0))
                cvss_version = "2.0"
                sev_raw = primary_metric.get("baseSeverity", "UNKNOWN").upper()
                cvss_severity = SeverityLevel(sev_raw) if sev_raw in SeverityLevel.__members__ else SeverityLevel.UNKNOWN

        # Concurrently fetch EPSS and check CISA KEV
        epss_task = asyncio.create_task(self.get_epss_score(cve_id))
        cisa_kev_data = self.get_cisa_kev_data(cve_id)
        epss_data = await epss_task

        return VulnerabilityData(
            cve_id=cve_id,
            cvss_score=cvss_score,
            cvss_version=cvss_version,
            cvss_severity=cvss_severity,
            cwe_id=cwe_id,
            cwe_name=cwe_name,
            description=description,
            epss=epss_data,
            cisa_kev=cisa_kev_data,
            references=references,
        )
