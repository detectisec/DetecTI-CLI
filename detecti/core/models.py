"""Unified Pydantic Models for DetecTI Findings and Intelligence."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class FindingType(str, Enum):
    """Enumeration of all supported finding types."""

    HOST_INFO = "HOST_INFO"
    SUBDOMAIN = "SUBDOMAIN"
    ASSOCIATED_DOMAIN = "ASSOCIATED_DOMAIN"
    OPEN_PORT = "OPEN_PORT"
    VULNERABILITY = "VULNERABILITY"
    EXPLOIT = "EXPLOIT"


class SeverityLevel(str, Enum):
    """CVSS / Risk severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class ExploitData(BaseModel):
    """Exploit and Proof of Concept metadata."""

    title: str = Field(..., description="Title or description of the exploit/PoC")
    source: str = Field(..., description="Source of the exploit (e.g., ExploitDB, GitHub, PacketStorm)")
    url: str = Field(..., description="Direct link or reference URL to the exploit")
    verified: bool = Field(default=False, description="Whether the exploit has been verified")
    author: Optional[str] = Field(default=None, description="Author or repository owner")
    date: Optional[str] = Field(default=None, description="Date published or released")
    exploit_type: Optional[str] = Field(default=None, description="Exploit classification (remote, local, web, dos)")


class CISAKEVData(BaseModel):
    """Details from CISA Known Exploited Vulnerabilities catalog."""

    in_cisa_kev: bool = Field(default=True, description="Whether the CVE is present in CISA KEV")
    vendor_project: Optional[str] = Field(default=None, description="Vendor or project name")
    product: Optional[str] = Field(default=None, description="Vulnerable product name")
    vulnerability_name: Optional[str] = Field(default=None, description="Name of the vulnerability in KEV")
    date_added: Optional[str] = Field(default=None, description="Date added to CISA KEV catalog")
    due_date: Optional[str] = Field(default=None, description="Remediation due date for federal agencies")
    required_action: Optional[str] = Field(default=None, description="Action required by CISA")
    known_ransomware_campaign_use: Optional[str] = Field(
        default=None, description="Known use in ransomware campaigns (Known/Unknown)"
    )
    notes: Optional[str] = Field(default=None, description="Additional CISA notes")


class EPSSData(BaseModel):
    """EPSS (Exploit Prediction Scoring System) metrics."""

    epss_score: float = Field(..., description="EPSS score between 0.0 and 1.0 (probability of exploitation in next 30 days)")
    epss_percentile: float = Field(..., description="EPSS percentile relative to all other scored CVEs (0.0 to 1.0)")
    date: Optional[str] = Field(default=None, description="EPSS scoring date")


class VulnerabilityData(BaseModel):
    """Vulnerability (CVE) enriched data with CVSS, EPSS, CISA KEV, and Exploits."""

    cve_id: str = Field(..., description="CVE identifier, e.g., CVE-2021-44228")
    cvss_score: Optional[float] = Field(default=None, description="CVSS Base Score (0.0 to 10.0)")
    cvss_version: Optional[str] = Field(default=None, description="CVSS version (e.g., '3.1', '3.0', '2.0')")
    cvss_severity: SeverityLevel = Field(default=SeverityLevel.UNKNOWN, description="CVSS qualitative severity rating")
    description: Optional[str] = Field(default=None, description="Summary or description of the vulnerability")
    cwe_id: Optional[str] = Field(default=None, description="CWE identifier, e.g., CWE-502")
    cwe_name: Optional[str] = Field(default=None, description="CWE weakness name, e.g., Deserialization of Untrusted Data")
    epss: Optional[EPSSData] = Field(default=None, description="EPSS prediction score")
    cisa_kev: Optional[CISAKEVData] = Field(default=None, description="CISA KEV catalog metadata")
    references: List[str] = Field(default_factory=list, description="List of reference URLs (from NVD or vendor)")
    exploits: List[ExploitData] = Field(default_factory=list, description="Public exploits and GitHub PoCs")

    @property
    def epss_score(self) -> Optional[float]:
        return self.epss.epss_score if self.epss else None

    @property
    def in_cisa_kev(self) -> bool:
        return bool(self.cisa_kev and self.cisa_kev.in_cisa_kev)


class PortData(BaseModel):
    """Detailed open port / service information."""

    port: int = Field(..., description="Port number")
    transport: str = Field(default="tcp", description="Transport protocol (tcp/udp)")
    service: Optional[str] = Field(default=None, description="Service name (http, ssh, etc.)")
    product: Optional[str] = Field(default=None, description="Software/Product name")
    version: Optional[str] = Field(default=None, description="Software version")
    banner: Optional[str] = Field(default=None, description="Raw service banner")
    url: Optional[str] = Field(default=None, description="Web URL if HTTP/HTTPS service")
    ssl: bool = Field(default=False, description="Whether SSL/TLS is enabled")
    sources: List[str] = Field(default_factory=list, description="Discovery sources for this port (e.g., Shodan, Censys)")

    @property
    def source(self) -> str:
        """Formatted string of unique sources that identified this port."""
        if not self.sources:
            return "Unknown"
        return ", ".join(dict.fromkeys(self.sources))


class HostInfoData(BaseModel):
    """Detailed host metadata from Shodan, Censys, or DNS."""

    ip: str = Field(..., description="IP address")
    hostnames: List[str] = Field(default_factory=list, description="Hostnames resolved")
    domains: List[str] = Field(default_factory=list, description="Domain names associated")
    org: Optional[str] = Field(default=None, description="Organization name")
    isp: Optional[str] = Field(default=None, description="ISP name")
    asn: Optional[str] = Field(default=None, description="Autonomous System Number")
    os: Optional[str] = Field(default=None, description="Operating System detected")
    country_name: Optional[str] = Field(default=None, description="Country name")
    country_code: Optional[str] = Field(default=None, description="Country 2-letter code")
    city: Optional[str] = Field(default=None, description="City name")
    region_code: Optional[str] = Field(default=None, description="State/Region code")
    postal_code: Optional[str] = Field(default=None, description="Postal / ZIP code")
    latitude: Optional[float] = Field(default=None, description="Latitude coordinate")
    longitude: Optional[float] = Field(default=None, description="Longitude coordinate")
    ports: List[int] = Field(default_factory=list, description="List of open port numbers")
    vulns: List[str] = Field(default_factory=list, description="List of CVE IDs identified")


class HostResult(BaseModel):
    """Complete host dossier encapsulating infrastructure, ports, and correlated vulnerabilities."""

    ip: str = Field(..., description="Host IP address")
    hostnames: List[str] = Field(default_factory=list, description="Hostnames pointing to this IP")
    domains: List[str] = Field(default_factory=list, description="Domains associated with this host")
    org: Optional[str] = Field(default=None, description="Organization name")
    isp: Optional[str] = Field(default=None, description="ISP name")
    asn: Optional[str] = Field(default=None, description="Autonomous System Number")
    os: Optional[str] = Field(default=None, description="Operating System")
    country_name: Optional[str] = Field(default=None, description="Country name")
    country_code: Optional[str] = Field(default=None, description="Country code")
    city: Optional[str] = Field(default=None, description="City name")
    region_code: Optional[str] = Field(default=None, description="State/Region code")
    postal_code: Optional[str] = Field(default=None, description="Postal / ZIP code")
    latitude: Optional[float] = Field(default=None, description="Latitude coordinate")
    longitude: Optional[float] = Field(default=None, description="Longitude coordinate")
    ports: List[PortData] = Field(default_factory=list, description="Open ports and running services")
    vulnerabilities: List[VulnerabilityData] = Field(
        default_factory=list,
        description="Enriched vulnerabilities specifically affecting this host",
    )
    sources: List[str] = Field(default_factory=list, description="Discovery sources that reported this host")
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def source(self) -> str:
        """Formatted string of unique sources that identified this host."""
        if not self.sources:
            return "Unknown"
        return ", ".join(dict.fromkeys(self.sources))


class Finding(BaseModel):
    """Standardized finding item produced by any ThreatTrack module."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique finding ID")
    type: FindingType = Field(..., description="Category of finding")
    target: str = Field(..., description="Input target that triggered the finding")
    value: str = Field(..., description="Primary finding value (domain, IP:port, CVE, etc.)")
    source: str = Field(..., description="Module/Data source that produced the finding")
    host_ip: Optional[str] = Field(default=None, description="Host IP this finding is associated with, if any")
    host_info: Optional[HostInfoData] = Field(default=None, description="Host metadata if applicable")
    port_info: Optional[PortData] = Field(default=None, description="Port metadata if applicable")
    vulnerability: Optional[VulnerabilityData] = Field(default=None, description="Vulnerability metadata if applicable")
    exploit: Optional[ExploitData] = Field(default=None, description="Exploit metadata if applicable")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional module-specific context")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when the finding was recorded",
    )


class ScanSummary(BaseModel):
    """Statistical summary of scan results."""

    total_findings: int = Field(default=0)
    total_hosts_count: int = Field(default=0)
    subdomains_count: int = Field(default=0)
    associated_domains_count: int = Field(default=0)
    open_ports_count: int = Field(default=0)
    vulnerabilities_count: int = Field(default=0)
    exploits_count: int = Field(default=0)
    cisa_kev_count: int = Field(default=0)
    critical_vulns_count: int = Field(default=0)
    high_vulns_count: int = Field(default=0)
    medium_vulns_count: int = Field(default=0)
    low_vulns_count: int = Field(default=0)


class ScanResult(BaseModel):
    """Complete results of a ThreatTrack execution."""

    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Scan identifier")
    target: str = Field(..., description="Original target queried")
    target_type: str = Field(default="unknown", description="Classified target type (ip, cidr, domain, query, file, cve)")
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = Field(default=None)
    elapsed_seconds: float = Field(default=0.0)
    modules_run: List[str] = Field(default_factory=list)
    hosts: List[HostResult] = Field(default_factory=list, description="Detailed per-host dossiers")
    findings: List[Finding] = Field(default_factory=list, description="All flattened findings")
    warnings: List[str] = Field(default_factory=list, description="API notices and runtime warning logs")
    summary: ScanSummary = Field(default_factory=ScanSummary)

    def calculate_summary(self) -> ScanSummary:
        """Compute the statistical summary across hosts and findings."""
        summary = ScanSummary(
            total_findings=len(self.findings),
            total_hosts_count=len(self.hosts),
        )
        seen_vulns = set()

        # Count from hosts if present
        for host in self.hosts:
            summary.open_ports_count += len(host.ports)
            for v in host.vulnerabilities:
                if v.cve_id not in seen_vulns:
                    seen_vulns.add(v.cve_id)
                    summary.vulnerabilities_count += 1
                    if v.in_cisa_kev:
                        summary.cisa_kev_count += 1
                    sev = v.cvss_severity
                    if sev == SeverityLevel.CRITICAL:
                        summary.critical_vulns_count += 1
                    elif sev == SeverityLevel.HIGH:
                        summary.high_vulns_count += 1
                    elif sev == SeverityLevel.MEDIUM:
                        summary.medium_vulns_count += 1
                    elif sev == SeverityLevel.LOW:
                        summary.low_vulns_count += 1
                    summary.exploits_count += len(v.exploits)

        # Count domain findings
        for finding in self.findings:
            if finding.type == FindingType.SUBDOMAIN:
                summary.subdomains_count += 1
            elif finding.type == FindingType.ASSOCIATED_DOMAIN:
                summary.associated_domains_count += 1
            elif finding.type == FindingType.OPEN_PORT and not self.hosts:
                summary.open_ports_count += 1
            elif finding.type == FindingType.EXPLOIT and not self.hosts:
                summary.exploits_count += 1
            elif finding.type == FindingType.VULNERABILITY and finding.vulnerability and not self.hosts:
                cve = finding.vulnerability.cve_id
                if cve not in seen_vulns:
                    seen_vulns.add(cve)
                    summary.vulnerabilities_count += 1
                    if finding.vulnerability.in_cisa_kev:
                        summary.cisa_kev_count += 1
                    sev = finding.vulnerability.cvss_severity
                    if sev == SeverityLevel.CRITICAL:
                        summary.critical_vulns_count += 1
                    elif sev == SeverityLevel.HIGH:
                        summary.high_vulns_count += 1
                    elif sev == SeverityLevel.MEDIUM:
                        summary.medium_vulns_count += 1
                    elif sev == SeverityLevel.LOW:
                        summary.low_vulns_count += 1
                    summary.exploits_count += len(finding.vulnerability.exploits)

        self.summary = summary
        return summary
