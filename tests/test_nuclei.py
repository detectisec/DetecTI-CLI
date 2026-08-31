"""Unit tests for Nuclei runner and database vulnerability merge."""

import pytest
import sqlite3
import tempfile
from pathlib import Path
from modules.nuclei import NucleiRunner
from core.database.schema import SCHEMA_SQL
from core.database.storage import DatabaseManager


def test_nuclei_runner_availability():
    runner = NucleiRunner()
    perm = runner.check_permissions()
    assert isinstance(perm, dict)
    assert "available" in perm
    assert "can_run" in perm


def test_nuclei_finding_normalization():
    runner = NucleiRunner()
    raw_sample = {
        "template-id": "cve-2021-44228",
        "info": {
            "name": "Apache Log4j RCE",
            "severity": "critical",
            "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.",
            "classification": {
                "cve-id": ["CVE-2021-44228"],
                "cwe-id": ["CWE-502"],
                "cvss-score": 10.0,
                "epss-score": 0.97
            },
            "reference": [
                "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                "https://github.com/advisories/GHSA-j2ge-4hvm-578x"
            ],
            "tags": ["cve", "rce", "log4j"]
        },
        "host": "http://192.168.1.100:8080",
        "matched-at": "http://192.168.1.100:8080",
        "ip": "192.168.1.100",
        "port": 8080
    }

    normalized = runner._normalize_finding(raw_sample)
    assert normalized is not None
    assert normalized["cve_id"] == "CVE-2021-44228"
    assert normalized["severity"] == "CRITICAL"
    assert normalized["cvss_score"] == 10.0
    assert normalized["epss_score"] == 0.97
    assert normalized["port"] == 8080
    assert len(normalized["references"]) == 2


def test_database_merge_nuclei_findings():
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
        db_path = Path(f.name)

    try:
        # Initialize schema
        with sqlite3.connect(db_path) as conn:
            conn.executescript(SCHEMA_SQL)
            conn.execute("INSERT INTO ip_addresses (id, ip, org) VALUES ('ip_1', '10.0.0.5', 'Acme Corp')")
            conn.execute("INSERT INTO services (id, ip_id, port, protocol, service_name, url) VALUES ('srv_1', 'ip_1', 8080, 'tcp', 'http', 'http://10.0.0.5:8080')")
            conn.commit()

        dm = DatabaseManager(db_path)
        findings = [
            {
                "template_id": "cve-2023-1234",
                "name": "Test Web Vulnerability",
                "severity": "HIGH",
                "cve_id": "CVE-2023-1234",
                "description": "High severity test finding",
                "cwe_id": "CWE-79",
                "cwe_name": "cve, xss",
                "cvss_score": 7.5,
                "epss_score": 0.45,
                "ip": "10.0.0.5",
                "port": 8080,
                "references": ["https://example.com/exploit/1"]
            }
        ]

        result = dm.merge_nuclei_findings(findings, fallback_ip="10.0.0.5")
        assert result["added_vulnerabilities"] == 1
        assert result["total_processed"] == 1

        # Verify in DB
        with sqlite3.connect(db_path) as conn:
            vuln_rows = conn.execute("SELECT cve_id, severity, cvss_score, service_id, ip_id FROM vulnerabilities").fetchall()
            assert len(vuln_rows) == 1
            assert vuln_rows[0][0] == "CVE-2023-1234"
            assert vuln_rows[0][1] == "HIGH"
            assert vuln_rows[0][2] == 7.5
            assert vuln_rows[0][3] == "srv_1"

            exploit_rows = conn.execute("SELECT url, source FROM exploits").fetchall()
            assert len(exploit_rows) == 1
            assert exploit_rows[0][0] == "https://example.com/exploit/1"
            assert exploit_rows[0][1] == "Nuclei"

        # Re-scan same vuln with updated description should deduplicate
        findings[0]["description"] = "Updated longer description for the same vulnerability"
        result2 = dm.merge_nuclei_findings(findings, fallback_ip="10.0.0.5")
        assert result2["updated_vulnerabilities"] == 1
        assert result2["added_vulnerabilities"] == 0

        with sqlite3.connect(db_path) as conn:
            count = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
            assert count == 1

    finally:
        if db_path.exists():
            db_path.unlink()


def test_nuclei_verified_active_ports_filter():
    from web.api.routes import _get_verified_active_services_for_ip, _format_nuclei_targets_from_services

    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
        db_path = Path(f.name)

    try:
        with sqlite3.connect(db_path) as conn:
            conn.executescript(SCHEMA_SQL)
            conn.execute("INSERT INTO ip_addresses (id, ip, org) VALUES ('ip_1', '192.168.1.50', 'Test Org')")
            # Passive service (not verified active)
            conn.execute(
                "INSERT INTO services (id, ip_id, port, protocol, service_name, sources) VALUES ('srv_passive', 'ip_1', 21, 'tcp', 'ftp', '[\"Shodan\"]')"
            )
            # Active service (verified by Masscan)
            conn.execute(
                "INSERT INTO services (id, ip_id, port, protocol, service_name, ssl, sources, banner) VALUES ('srv_active', 'ip_1', 443, 'tcp', 'https', 1, '[\"Masscan\"]', 'nginx')"
            )
            conn.commit()

        dm = DatabaseManager(db_path)
        active_svcs = _get_verified_active_services_for_ip("192.168.1.50", dm)
        
        # Only the masscan/active port should be included
        assert len(active_svcs) == 1
        assert active_svcs[0]["port"] == 443
        
        targets = _format_nuclei_targets_from_services("192.168.1.50", active_svcs)
        assert targets == ["https://192.168.1.50:443"]

    finally:
        if db_path.exists():
            db_path.unlink()


@pytest.mark.anyio
async def test_nuclei_runner_scan_targets_empty():
    runner = NucleiRunner()
    res = await runner.scan_targets(targets=[], severities=["critical"])
    assert res["success"] is True
    assert res["total_findings"] == 0


