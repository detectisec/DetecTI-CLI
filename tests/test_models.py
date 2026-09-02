"""Unit tests for ThreatTrack Pydantic models."""

from datetime import datetime, timezone
from pathlib import Path
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


def test_graph_builder_target_root_hierarchy(tmp_path: Path):
    """Test that GraphBuilder constructs hierarchy: Target Domain -> Subdomains -> IPs -> Services -> Vulnerabilities."""
    from core.database.storage import DatabaseManager
    from web.api.graph_builder import GraphBuilder

    db_file = tmp_path / "test_target.sqlite"
    db_manager = DatabaseManager(db_file)

    # Build sample ScanResult with target="alvo.com"
    scan_res = ScanResult(
        target="alvo.com",
        target_type="domain",
    )

    # Subdomains findings
    scan_res.findings = [
        Finding(
            type=FindingType.SUBDOMAIN,
            target="alvo.com",
            value="api.alvo.com",
            source="crt.sh",
        ),
        Finding(
            type=FindingType.SUBDOMAIN,
            target="alvo.com",
            value="vpn.alvo.com",
            source="crt.sh",
        ),
    ]

    # Host resolved from domain and subdomain
    host = HostResult(
        ip="10.20.30.40",
        org="Alvo Corp",
        country_name="Brazil",
        hostnames=["alvo.com", "api.alvo.com"],
        domains=["alvo.com"],
        ports=[
            PortData(port=443, transport="tcp", product="nginx", version="1.21.0", ssl=True, url="https://api.alvo.com:443")
        ],
        vulnerabilities=[
            VulnerabilityData(
                cve_id="CVE-2023-1234",
                cvss_score=8.5,
                cvss_severity=SeverityLevel.HIGH,
                description="High severity vulnerability on nginx",
            )
        ],
    )
    scan_res.hosts = [host]
    scan_res.calculate_summary()

    # Store in database
    db_manager.store_scan_result(scan_res)

    # Build Graph
    builder = GraphBuilder(db_manager)
    graph = builder.build_graph()

    nodes = graph["elements"]["nodes"]
    edges = graph["elements"]["edges"]

    # 1. Target Root node exists as primary anchor with embedded DNS inventory
    target_root = next((n for n in nodes if n["data"]["id"] == "target_root"), None)
    assert target_root is not None
    assert target_root["data"]["is_root"] is True
    assert target_root["data"]["total_subdomains"] == 2
    assert len(target_root["data"]["all_subdomains"]) == 2

    # 2. IP node exists with associated FQDN metadata
    ip_nodes = [n for n in nodes if n["data"]["type"] == "ip"]
    assert len(ip_nodes) == 1
    assert ip_nodes[0]["data"]["ip"] == "10.20.30.40"
    assert "api.alvo.com" in ip_nodes[0]["data"]["fqdns"]

    # 3. Check hierarchy edges: Target Root -> Domain (CONTAINS_TARGET) -> IP (RESOLVES_TO)
    target_edges = [e for e in edges if e["data"]["label"] == "CONTAINS_TARGET"]
    assert len(target_edges) >= 1
    dom_nodes = [n for n in nodes if n["data"]["type"] == "domain"]
    assert len(dom_nodes) == 1
    assert any(e["data"]["source"] == "target_root" and e["data"]["target"] == dom_nodes[0]["data"]["id"] for e in target_edges)

    resolves_edges = [e for e in edges if e["data"]["label"] == "RESOLVES_TO"]
    assert len(resolves_edges) >= 1
    assert any(e["data"]["source"] == dom_nodes[0]["data"]["id"] and e["data"]["target"] == ip_nodes[0]["data"]["id"] for e in resolves_edges)

    # 4. IP -> Service (EXPOSES)
    ip_srv_edges = [e for e in edges if e["data"]["label"] == "EXPOSES"]
    assert len(ip_srv_edges) >= 1

    # 5. Service -> Vulnerability (HAS_VULN)
    srv_vuln_edges = [e for e in edges if e["data"]["label"] == "HAS_VULN"]
    assert len(srv_vuln_edges) >= 1

    # 6. Test explicit target promotion (api.alvo.com materializes as node when active target)
    graph_with_target = builder.build_graph(active_targets=["api.alvo.com"])
    target_nodes = graph_with_target["elements"]["nodes"]
    target_edge_list = graph_with_target["elements"]["edges"]
    sub_nodes = [n for n in target_nodes if n["data"]["type"] == "subdomain"]
    assert len(sub_nodes) == 1
    assert sub_nodes[0]["data"]["name"] == "api.alvo.com"
    assert any(e["data"]["source"] == "target_root" and e["data"]["target"] == sub_nodes[0]["data"]["id"] for e in target_edge_list)
    assert any(e["data"]["source"] == sub_nodes[0]["data"]["id"] and e["data"]["label"] == "RESOLVES_TO" for e in target_edge_list)

    # 7. Test file target permanent materialization of explicit subdomains
    import sqlite3
    with sqlite3.connect(db_file) as conn:
        conn.execute("UPDATE scan_results SET target = 'scope_targets.txt', target_type = 'file'")
        conn.commit()

    graph_file_target = builder.build_graph()
    file_nodes = graph_file_target["elements"]["nodes"]
    file_edges = graph_file_target["elements"]["edges"]
    file_sub_nodes = [n for n in file_nodes if n["data"]["type"] == "subdomain"]
    assert len(file_sub_nodes) >= 1
    assert any(n["data"]["name"] == "api.alvo.com" for n in file_sub_nodes)
    assert any(e["data"]["source"] == "target_root" and e["data"]["label"] == "CONTAINS_TARGET" for e in file_edges)
