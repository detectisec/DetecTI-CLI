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
