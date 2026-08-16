"""Unit tests for ThreatTrack Pydantic models."""

from datetime import datetime, timezone
import pytest
from core.models import (
    CISAKEVData,
    EPSSData,
    ExploitData,
    Finding,
    FindingType,
    HostInfoData,
    HostResult,
    PortData,
    ScanResult,
    SeverityLevel,
    VulnerabilityData,
)


def test_exploit_data_model():
    """Test ExploitData validation and serialization."""
    exploit = ExploitData(
        title="Log4j RCE",
        source="GitHub",
        url="https://github.com/example/log4j-poc",
        verified=True,
        author="researcher",
    )
    assert exploit.title == "Log4j RCE"
    assert exploit.source == "GitHub"
    assert exploit.verified is True
    assert exploit.author == "researcher"


def test_vulnerability_data_model():
    """Test VulnerabilityData with EPSS and CISA KEV."""
    epss = EPSSData(epss_score=0.975, epss_percentile=0.99)
    kev = CISAKEVData(
        in_cisa_kev=True,
        vendor_project="Apache",
        product="Log4j",
        vulnerability_name="Apache Log4j RCE",
        date_added="2021-12-10",
        required_action="Apply vendor updates",
    )
    vuln = VulnerabilityData(
        cve_id="CVE-2021-44228",
        cvss_score=10.0,
        cvss_version="3.1",
        cvss_severity=SeverityLevel.CRITICAL,
        cwe_id="CWE-502",
        cwe_name="Deserialization of Untrusted Data",
        description="Remote code execution in Log4j",
        epss=epss,
        cisa_kev=kev,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    )

    assert vuln.cve_id == "CVE-2021-44228"
    assert vuln.cwe_id == "CWE-502"
    assert vuln.cwe_name == "Deserialization of Untrusted Data"
    assert vuln.cvss_score == 10.0
    assert vuln.cvss_severity == SeverityLevel.CRITICAL
    assert vuln.in_cisa_kev is True
    assert vuln.epss_score == 0.975


def test_host_result_model():
    """Test HostResult containing dedicated ports and vulnerabilities."""
    host = HostResult(
        ip="192.168.1.50",
        org="Example Corp",
        os="Linux 5.15",
        ports=[PortData(port=80, transport="tcp", product="Apache", version="2.4.49")],
        vulnerabilities=[
            VulnerabilityData(
                cve_id="CVE-2021-41773",
                cvss_score=7.5,
                cvss_severity=SeverityLevel.HIGH,
                epss=EPSSData(epss_score=0.95, epss_percentile=0.98),
                cisa_kev=CISAKEVData(in_cisa_kev=True),
            )
        ],
    )

    assert host.ip == "192.168.1.50"
    assert len(host.ports) == 1
    assert len(host.vulnerabilities) == 1
    assert host.vulnerabilities[0].cve_id == "CVE-2021-41773"
    assert host.vulnerabilities[0].in_cisa_kev is True


def test_finding_and_scan_result_summary():
    """Test ScanResult calculation of summary statistics with HostResult."""
    result = ScanResult(
        target="example.com",
        target_type="domain",
    )

    host = HostResult(
        ip="1.2.3.4",
        org="Example Corp",
        ports=[PortData(port=443, transport="tcp", product="nginx", version="1.20")],
        vulnerabilities=[
            VulnerabilityData(
                cve_id="CVE-2021-44228",
                cvss_score=10.0,
                cvss_severity=SeverityLevel.CRITICAL,
                cisa_kev=CISAKEVData(in_cisa_kev=True),
                exploits=[
                    ExploitData(
                        title="PoC",
                        source="GitHub",
                        url="https://github.com/poc",
                    )
                ],
            )
        ],
    )

    result.hosts = [host]
    result.findings = [
        Finding(
            type=FindingType.SUBDOMAIN,
            target="example.com",
            value="api.example.com",
            source="crt.sh",
        ),
        Finding(
            type=FindingType.ASSOCIATED_DOMAIN,
            target="example.com",
            value="example.net",
            source="reverse_whois",
        ),
    ]

    summary = result.calculate_summary()

    assert summary.total_hosts_count == 1
    assert summary.subdomains_count == 1
    assert summary.associated_domains_count == 1
    assert summary.open_ports_count == 1
    assert summary.vulnerabilities_count == 1
    assert summary.critical_vulns_count == 1
    assert summary.cisa_kev_count == 1
    assert summary.exploits_count == 1
