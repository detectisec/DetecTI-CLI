"""Unit tests for JSON and Markdown Reporters."""

import json
from pathlib import Path
from core.models import (
    CISAKEVData,
    EPSSData,
    ExploitData,
    Finding,
    FindingType,
    HostResult,
    PortData,
    ScanResult,
    SeverityLevel,
    VulnerabilityData,
)
from reporters.html_reporter import HTMLReporter
from reporters.json_reporter import JSONReporter
from reporters.markdown_reporter import MarkdownReporter


def create_sample_scan_result() -> ScanResult:
    """Create a sample ScanResult with HostResult for reporter tests."""
    result = ScanResult(
        target="192.168.1.50",
        target_type="ip",
    )
    host = HostResult(
        ip="192.168.1.50",
        org="Example Corp",
        os="Linux",
        ports=[PortData(port=80, transport="tcp", product="Apache", version="2.4.49", url="http://192.168.1.50:80")],
        vulnerabilities=[
            VulnerabilityData(
                cve_id="CVE-2021-41773",
                cvss_score=7.5,
                cvss_version="3.1",
                cvss_severity=SeverityLevel.HIGH,
                epss=EPSSData(epss_score=0.95, epss_percentile=0.98),
                cisa_kev=CISAKEVData(in_cisa_kev=True, vulnerability_name="Apache HTTP Server Path Traversal"),
                exploits=[
                    ExploitData(title="Apache 2.4.49 Exploit", source="ExploitDB", url="https://exploit-db.com/exploits/50383")
                ],
            )
        ],
    )
    result.hosts = [host]
    result.calculate_summary()
    return result


def test_json_reporter(tmp_path: Path):
    """Test JSON reporter generation and save."""
    result = create_sample_scan_result()
    json_str = JSONReporter.generate(result)
    data = json.loads(json_str)

    assert data["target"] == "192.168.1.50"
    assert len(data["hosts"]) == 1
    assert data["hosts"][0]["ip"] == "192.168.1.50"
    assert len(data["hosts"][0]["vulnerabilities"]) == 1
    assert data["summary"]["cisa_kev_count"] == 1

    file_path = tmp_path / "report.json"
    JSONReporter.save(result, file_path)
    assert file_path.is_file()


def test_markdown_reporter(tmp_path: Path):
    """Test Markdown reporter generation and save."""
    result = create_sample_scan_result()
    md_content = MarkdownReporter.generate(result)

    assert "# DetecTI Cyber Lead Intelligence Report: `192.168.1.50`" in md_content
    assert "CVE-2021-41773" in md_content
    assert "CWE Name" in md_content
    assert "CISA Known Exploited" in md_content
    assert "50383" in md_content
    assert "Host: `192.168.1.50`" in md_content
    assert "https://detecti.com.br" in md_content

    file_path = tmp_path / "report.md"
    MarkdownReporter.save(result, file_path)
    assert file_path.is_file()


def test_html_reporter(tmp_path: Path):
    """Test HTML reporter generation and save."""
    result = create_sample_scan_result()
    html_content = HTMLReporter.generate(result)

    assert "<!DOCTYPE html>" in html_content
    assert "192.168.1.50" in html_content
    assert "CVE-2021-41773" in html_content
    assert "DetecTI-CLI Intelligence Report" in html_content
    assert "https://detecti.com.br" in html_content

    file_path = tmp_path / "report.html"
    HTMLReporter.save(result, file_path)
    assert file_path.is_file()
    assert file_path.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")

