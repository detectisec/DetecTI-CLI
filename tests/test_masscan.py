"""Tests for Masscan active port scanner and active scan database merge."""

import asyncio
import json
import tempfile
from pathlib import Path
from modules.masscan import MasscanRunner
from core.database.storage import DatabaseManager


def test_masscan_runner_permissions():
    """Test MasscanRunner permission check."""
    runner = MasscanRunner()
    perm = runner.check_permissions()
    assert isinstance(perm, dict)
    assert "available" in perm
    assert "is_root" in perm


def test_masscan_json_parser():
    """Test masscan JSON parsing with various formats, banners, and multi-record consolidation."""
    runner = MasscanRunner()
    sample_json = [
        {
            "ip": "1.1.1.1",
            "timestamp": "1620000000",
            "ports": [
                {
                    "port": 80,
                    "proto": "tcp",
                    "status": "open",
                    "ttl": 56
                }
            ]
        },
        {
            "ip": "1.1.1.1",
            "timestamp": "1620000001",
            "ports": [
                {
                    "port": 80,
                    "proto": "tcp",
                    "service": {
                        "name": "http",
                        "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52\r\n"
                    }
                },
                {
                    "port": 443,
                    "proto": "tcp",
                    "status": "open",
                    "ttl": 56,
                    "service": {
                        "name": "https"
                    }
                }
            ]
        }
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(sample_json, f)
        temp_path = f.name

    try:
        parsed = runner._parse_json_file(temp_path, "1.1.1.1")
        assert len(parsed) == 2  # Consolidated port 80 and 443
        assert parsed[0]["port"] == 80
        assert parsed[0]["service_name"] == "http"
        assert "Apache/2.4.52" in parsed[0]["banner"]
        assert parsed[0]["product"] == "Apache"
        assert parsed[0]["version"] == "2.4.52"
        assert parsed[1]["port"] == 443
        assert parsed[1]["ssl"] is True
    finally:
        Path(temp_path).unlink(missing_ok=True)


def test_database_merge_active_scan_services():
    """Test merging active scan services into SQLite database with deduplication and banner consistency."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_target.sqlite"
        db = DatabaseManager(db_path)

        # 1. Merge new active scan services on new IP
        open_ports = [
            {"port": 80, "protocol": "tcp", "service_name": "http", "product": "Apache", "version": "2.4", "banner": "Apache/2.4"},
            {"port": 443, "protocol": "tcp", "service_name": "https", "ssl": True},
        ]
        res1 = db.merge_active_scan_services("192.168.1.10", open_ports)
        assert res1["added_services"] == 2
        assert res1["updated_services"] == 0

        # 2. Merge updated active scan services with new banner/version
        open_ports_update = [
            {"port": 80, "protocol": "tcp", "service_name": "http", "product": "Apache", "version": "2.4.52", "banner": "Apache/2.4.52 (Ubuntu)"},
            {"port": 8080, "protocol": "tcp", "service_name": "http-proxy", "ssl": False},
        ]
        res2 = db.merge_active_scan_services("192.168.1.10", open_ports_update)
        assert res2["added_services"] == 1  # 8080 added
        assert res2["updated_services"] == 1  # 80 updated

        stats = db.get_summary_stats()
        assert stats["total_ips"] == 1
        assert stats["open_services"] == 3

        # Verify that banner and version were updated in SQLite
        import sqlite3
        with sqlite3.connect(db_path) as conn:
            row = conn.execute("SELECT banner, product, version, sources FROM services WHERE port = 80").fetchone()
            assert row[0] == "Apache/2.4.52 (Ubuntu)"
            assert row[1] == "Apache"
            assert row[2] == "2.4.52"
            assert "Masscan" in row[3]


def test_build_port_ranges_excluding():
    """Test generating contiguous port ranges excluding specified ports."""
    from modules.masscan import build_port_ranges_excluding

    # 1. No excluded ports
    assert build_port_ranges_excluding(0, 65535, set()) == "0-65535"
    assert build_port_ranges_excluding(1, 100, set()) == "1-100"

    # 2. Exclude ports 80 and 443 from 0-65535
    res = build_port_ranges_excluding(0, 65535, {80, 443})
    assert res == "0-79,81-442,444-65535"

    # 3. Exclude edge ports (0, 65535)
    res_edge = build_port_ranges_excluding(0, 65535, {0, 65535})
    assert res_edge == "1-65534"

    # 4. Exclude adjacent ports
    res_adj = build_port_ranges_excluding(1, 10, {2, 3, 4})
    assert res_adj == "1,5-10"


def test_filter_ports_excluding():
    """Test filtering port specifications with excluded confirmed active ports."""
    from modules.masscan import filter_ports_excluding, parse_port_spec_to_set

    # 1. Discrete port list
    filtered, remaining, excluded = filter_ports_excluding("80,443,8080,8443", {80, 443})
    assert filtered == "8080,8443"
    assert remaining == 2
    assert excluded == 2

    # 2. All requested ports already confirmed active
    filtered_all, rem_all, ex_all = filter_ports_excluding("80,443", {80, 443})
    assert filtered_all is None
    assert rem_all == 0
    assert ex_all == 2

    # 3. All ports 0-65535 with exclusions
    filtered_65k, rem_65k, ex_65k = filter_ports_excluding("0-65535", {80, 443})
    assert filtered_65k == "0-79,81-442,444-65535"
    assert rem_65k == 65534
    assert ex_65k == 2

    # 4. Top 100 ports with exclusions
    filtered_top, rem_top, ex_top = filter_ports_excluding("--top-ports 100", {80, 443})
    assert rem_top == 98
    assert ex_top == 2
    assert "80" not in parse_port_spec_to_set(filtered_top)
    assert "443" not in parse_port_spec_to_set(filtered_top)


def test_target_ports_partition():
    """Test database querying for verified active vs unverified passive ports."""
    from web.api.routes import _get_target_ports_partition

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_partition.sqlite"
        db = DatabaseManager(db_path)

        # Populate test IP and services
        import sqlite3
        with sqlite3.connect(db_path) as conn:
            conn.execute("INSERT INTO ip_addresses (id, ip) VALUES ('ip-1', '10.0.0.1')")
            # Verified Active service (Masscan)
            conn.execute(
                "INSERT INTO services (id, ip_id, port, protocol, sources) VALUES ('s1', 'ip-1', 80, 'tcp', ?)",
                (json.dumps(["Masscan", "Shodan"]),)
            )
            # Unverified passive service (Shodan only)
            conn.execute(
                "INSERT INTO services (id, ip_id, port, protocol, sources) VALUES ('s2', 'ip-1', 8080, 'tcp', ?)",
                (json.dumps(["Shodan"]),)
            )
            # Unverified passive service (Censys only)
            conn.execute(
                "INSERT INTO services (id, ip_id, port, protocol, sources) VALUES ('s3', 'ip-1', 8443, 'tcp', ?)",
                (json.dumps(["Censys"]),)
            )

        verified, unverified = _get_target_ports_partition("10.0.0.1", db)
        assert verified == {80}
        assert unverified == {8080, 8443}

