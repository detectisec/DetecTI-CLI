"""Unit tests for ThreatTrack Engine and Typer CLI."""

import sys
from pathlib import Path
import pytest
from typer.testing import CliRunner

# Add the project root to sys.path to import the CLI module
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import importlib.machinery
    cli_path = (Path(__file__).parent.parent / "detecti-cli").resolve()
    loader = importlib.machinery.SourceFileLoader("detecti_cli", str(cli_path))
    detecti_cli = loader.load_module()
    app = detecti_cli.app
except Exception as e:
    detecti_cli = None
    app = None

from core.engine import ThreatTrackEngine, DetectIEngine
from core.models import Finding, FindingType, PortData

runner = CliRunner()


def test_engine_target_classification():
    """Test classification of various input target formats."""
    engine = ThreatTrackEngine()

    assert engine.classify_target("142.250.191.68") == "ip"
    assert engine.classify_target("host:142.250.191.68") == "ip"
    assert engine.classify_target("142.250.191.0/24") == "cidr"
    assert engine.classify_target("host:142.250.191.0/24") == "cidr"
    assert engine.classify_target("spacex.com") == "domain"
    assert engine.classify_target("domain:spacex.com") == "domain"
    assert engine.classify_target("admin@domain.com") == "email"
    assert engine.classify_target("org:google product:OpenSSH") == "query"

    with pytest.raises(FileNotFoundError):
        engine.parse_target_metadata("nonexistent_targets.txt")


def test_cli_nonexistent_file_rejection():
    """Test that non-existent file targets are rejected with error and exit code 1."""
    if app is None:
        pytest.skip("CLI app not available")
    res = runner.invoke(app, ["scan", "-t", "nonexistent_targets_file.txt"])
    assert res.exit_code == 1
    assert "Target file not found" in res.stdout


def test_cli_version():
    """Test CLI version command."""
    if app is None:
        pytest.skip("CLI app not available")
    res = runner.invoke(app, ["version"])
    assert res.exit_code == 0
    assert "DetecTI-CLI" in res.stdout


def test_cli_config_check():
    """Test CLI config-check command."""
    if app is None:
        pytest.skip("CLI app not available")
    res = runner.invoke(app, ["config-check"])
    assert res.exit_code == 0
    assert "System & Environment Diagnostics" in res.stdout
    assert "Shodan" in res.stdout


def test_cli_setup():
    """Test CLI setup command."""
    if app is None:
        pytest.skip("CLI app not available")
    res = runner.invoke(app, ["setup"])
    assert res.exit_code == 0
    assert "Automated Environment Setup" in res.stdout
    assert "Verification Diagnostics" in res.stdout


def test_setup_manager_checks():
    """Test SetupManager diagnostic check suite."""
    from utils.setup import SetupManager
    mgr = SetupManager()
    checks = mgr.check_all()
    assert "python_version" in checks
    assert "python_modules" in checks
    assert "directories" in checks
    assert "env_file" in checks
    assert "masscan" in checks
    assert "nuclei" in checks
    assert "exploitdb" in checks
    assert checks["python_version"]["ok"] is True


def test_target_parsing_and_normalization():
    """Test engine target normalization across URLs, subdomains, ports, and raw targets."""
    engine = ThreatTrackEngine()

    # URL with domain
    meta1 = engine.parse_target_metadata("https://spacex.com")
    assert meta1["type"] == "domain"
    assert meta1["clean_target"] == "spacex.com"
    assert meta1["root_domain"] == "spacex.com"

    # URL with subdomain, path and port
    meta2 = engine.parse_target_metadata("https://api.spacex.com:8443/v1/health")
    assert meta2["type"] == "domain"
    assert meta2["clean_target"] == "api.spacex.com"
    assert meta2["root_domain"] == "spacex.com"
    assert meta2["subdomain"] == "api"
    assert meta2["port"] == 8443

    # URL with IP and port
    meta3 = engine.parse_target_metadata("https://192.168.1.10:8080/admin")
    assert meta3["type"] == "ip"
    assert meta3["clean_target"] == "192.168.1.10"
    assert meta3["port"] == 8080

    # Subdomain with multiple levels
    meta4 = engine.parse_target_metadata("sub.corp.example.com.br")
    assert meta4["type"] == "domain"
    assert meta4["clean_target"] == "sub.corp.example.com.br"
    assert meta4["root_domain"] == "example.com.br"
    assert meta4["subdomain"] == "sub.corp"


def test_target_to_db_name_url():
    """Test database name generation from URL and subdomain targets."""
    if detecti_cli is None:
        pytest.skip("CLI not imported")
    target_to_db_name = detecti_cli.target_to_db_name
    assert target_to_db_name("https://api.spacex.com/v1") == "api.spacex.com.sqlite"
    assert target_to_db_name("http://sub.domain.com.br:8080/") == "sub.domain.com.br.sqlite"
    assert target_to_db_name("https://192.168.1.1:8443") == "192.168.1.1.sqlite"


def test_engine_multi_source_correlation(monkeypatch):
    """Test that Shodan and Censys findings are deduplicated and enriched with combined sources."""
    import asyncio
    from core.models import Finding, FindingType, HostInfoData, PortData
    from modules.shodan import ShodanModule
    from modules.censys import CensysModule

    async def _test():
        engine = ThreatTrackEngine()

        shodan_findings = [
            Finding(
                type=FindingType.HOST_INFO,
                target="1.2.3.4",
                value="1.2.3.4",
                source="Shodan",
                host_ip="1.2.3.4",
                host_info=HostInfoData(
                    ip="1.2.3.4",
                    org="Example Corp",
                    asn="AS12345",
                    ports=[80, 443],
                ),
            ),
            Finding(
                type=FindingType.OPEN_PORT,
                target="1.2.3.4",
                value="1.2.3.4:80",
                source="Shodan",
                host_ip="1.2.3.4",
                port_info=PortData(port=80, transport="tcp", product="Apache", version="2.4.50", sources=["Shodan"]),
            ),
            Finding(
                type=FindingType.OPEN_PORT,
                target="1.2.3.4",
                value="1.2.3.4:443",
                source="Shodan",
                host_ip="1.2.3.4",
                port_info=PortData(port=443, transport="tcp", product="nginx", sources=["Shodan"]),
            ),
        ]

        censys_findings = [
            Finding(
                type=FindingType.HOST_INFO,
                target="1.2.3.4",
                value="1.2.3.4",
                source="Censys",
                host_ip="1.2.3.4",
                host_info=HostInfoData(
                    ip="1.2.3.4",
                    country_name="Brazil",
                    city="Sao Paulo",
                    ports=[80, 443, 3000],
                ),
            ),
            Finding(
                type=FindingType.OPEN_PORT,
                target="1.2.3.4",
                value="1.2.3.4:80",
                source="Censys",
                host_ip="1.2.3.4",
                port_info=PortData(
                    port=80,
                    transport="tcp",
                    banner="Apache HTTP Server",
                    url="http://1.2.3.4:80",
                    sources=["Censys"],
                ),
            ),
            Finding(
                type=FindingType.OPEN_PORT,
                target="1.2.3.4",
                value="1.2.3.4:443",
                source="Censys",
                host_ip="1.2.3.4",
                port_info=PortData(port=443, transport="tcp", ssl=True, sources=["Censys"]),
            ),
            Finding(
                type=FindingType.OPEN_PORT,
                target="1.2.3.4",
                value="1.2.3.4:3000",
                source="Censys",
                host_ip="1.2.3.4",
                port_info=PortData(port=3000, transport="tcp", product="Grafana", url="http://1.2.3.4:3000", sources=["Censys"]),
            ),
        ]

        async def mock_shodan_run(self, target, context=None):
            return shodan_findings

        async def mock_censys_run(self, target, context=None):
            return censys_findings

        monkeypatch.setattr(ShodanModule, "is_configured", lambda self: True)
        monkeypatch.setattr(CensysModule, "is_configured", lambda self: True)
        monkeypatch.setattr(ShodanModule, "run", mock_shodan_run)
        monkeypatch.setattr(CensysModule, "run", mock_censys_run)

        result = await engine.scan("1.2.3.4", enabled_modules=["shodan", "censys"])

        assert len(result.hosts) == 1
        host = result.hosts[0]
        assert host.ip == "1.2.3.4"
        assert host.org == "Example Corp"
        assert host.country_name == "Brazil"
        assert "Shodan" in host.sources
        assert "Censys" in host.sources
        assert host.source == "Shodan, Censys"

        # Check ports deduplication: exactly 3 ports (80, 443, 3000)
        assert len(host.ports) == 3
        ports_by_num = {p.port: p for p in host.ports}

        # Port 80 should be complemented by both sources
        p80 = ports_by_num[80]
        assert "Shodan" in p80.sources
        assert "Censys" in p80.sources
        assert p80.source == "Shodan, Censys"
        assert p80.product == "Apache"
        assert p80.version == "2.4.50"
        assert p80.banner == "Apache HTTP Server"
        assert p80.url == "http://1.2.3.4:80"

        # Port 443
        p443 = ports_by_num[443]
        assert p443.source == "Shodan, Censys"
        assert p443.product == "nginx"
        assert p443.ssl is True

        # Port 3000
        p3000 = ports_by_num[3000]
        assert p3000.source == "Censys"
        assert p3000.product == "Grafana"

    asyncio.run(_test())


def test_engine_unlimited_host_enrichment(monkeypatch):
    """Test that engine enriches ALL discovered host IPs (e.g. 50+ IPs) without artificial 25 IP caps."""
    import asyncio
    from core.models import Finding, FindingType, HostInfoData
    from modules.shodan import ShodanModule
    from modules.censys import CensysModule

    async def _test():
        engine = ThreatTrackEngine()

        discovered_50_ips = [f"10.0.0.{i}" for i in range(1, 51)]
        shodan_findings = [
            Finding(
                type=FindingType.HOST_INFO,
                target="query:test",
                value=ip,
                source="Shodan",
                host_ip=ip,
                host_info=HostInfoData(ip=ip, ports=[80]),
            )
            for ip in discovered_50_ips
        ]

        censys_queried_ips = []

        async def mock_shodan_run(self, target, context=None):
            return shodan_findings

        async def mock_censys_run(self, target, context=None):
            return []

        async def mock_censys_get_host(self, ip):
            censys_queried_ips.append(ip)
            return [
                Finding(
                    type=FindingType.OPEN_PORT,
                    target=ip,
                    value=f"{ip}:443",
                    source="Censys",
                    host_ip=ip,
                    port_info=PortData(port=443, transport="tcp", sources=["Censys"]),
                )
            ]

        monkeypatch.setattr(ShodanModule, "is_configured", lambda self: True)
        monkeypatch.setattr(CensysModule, "is_configured", lambda self: True)
        monkeypatch.setattr(ShodanModule, "run", mock_shodan_run)
        monkeypatch.setattr(CensysModule, "run", mock_censys_run)
        monkeypatch.setattr(CensysModule, "get_host_info", mock_censys_get_host)

        result = await engine.scan("org:test", enabled_modules=["shodan", "censys"])

        # Engine must have enriched all 50 discovered IPs, not just 25
        assert len(result.hosts) == 50
        assert len(censys_queried_ips) == 50
        assert set(censys_queried_ips) == set(discovered_50_ips)

    asyncio.run(_test())


def test_database_api_list_and_delete(tmp_path):
    """Test GET /databases strips .sqlite for clean target display and POST /databases/delete works."""
    from web.server import create_app
    from fastapi.testclient import TestClient

    app = create_app()
    client = TestClient(app)

    # Create dummy sqlite db in ./data/dbs/
    dbs_dir = Path.cwd() / "data" / "dbs"
    dbs_dir.mkdir(parents=True, exist_ok=True)
    test_db = dbs_dir / "test_target_dummy.sqlite"
    test_db.write_text("test")

    try:
        res = client.get("/api/v1/databases")
        assert res.status_code == 200
        data = res.json()
        assert "databases" in data
        
        # Check that test_target_dummy is present with clean name
        found = [d for d in data["databases"] if d["filename"] == "test_target_dummy.sqlite"]
        assert len(found) == 1
        assert found[0]["clean_name"] == "test_target_dummy"
        assert not found[0]["clean_name"].endswith(".sqlite")

        # Delete database via API
        del_res = client.post("/api/v1/databases/delete", json={"name": "test_target_dummy"})
        assert del_res.status_code == 200
        assert del_res.json()["success"] is True
        assert not test_db.exists()
    finally:
        if test_db.exists():
            test_db.unlink()


def test_recursive_subdomain_and_ip_feedback_loop(monkeypatch):
    """Test that subdomains discovered via crt.sh/recon are resolved to IPs and retrofed to Shodan/Censys."""
    import asyncio
    from core.engine import ThreatTrackEngine
    from modules.crtsh import CrtshModule
    from modules.shodan import ShodanModule
    from core.models import Finding, FindingType, PortData

    async def _test():
        engine = ThreatTrackEngine()
        
        # 1. Mock Crtsh to discover 2 subdomains
        async def mock_crtsh_run(self, target, context=None):
            return [
                Finding(
                    type=FindingType.SUBDOMAIN,
                    target=target,
                    value="api.example.com",
                    source="crt.sh",
                ),
                Finding(
                    type=FindingType.SUBDOMAIN,
                    target=target,
                    value="vpn.example.com",
                    source="crt.sh",
                ),
            ]

        # 2. Mock DNS resolution
        async def mock_getaddrinfo(host, port):
            if host == "api.example.com":
                return [(None, None, None, None, ("198.51.100.10", 0))]
            elif host == "vpn.example.com":
                return [(None, None, None, None, ("198.51.100.20", 0))]
            return []

        # 3. Mock Shodan get_host_info to track retrofed IPs
        shodan_retrofed_ips = []

        async def mock_shodan_get_host(self, ip):
            shodan_retrofed_ips.append(ip)
            return [
                Finding(
                    type=FindingType.OPEN_PORT,
                    target=ip,
                    value=f"{ip}:443",
                    source="Shodan",
                    host_ip=ip,
                    port_info=PortData(port=443, transport="tcp", service="https", sources=["Shodan"]),
                ),
                Finding(
                    type=FindingType.VULNERABILITY,
                    target=ip,
                    value="CVE-2024-1234",
                    source="Shodan",
                    host_ip=ip,
                )
            ]

        async def mock_shodan_run(self, target, context=None):
            return []

        monkeypatch.setattr(CrtshModule, "is_configured", lambda self: True)
        monkeypatch.setattr(CrtshModule, "run", mock_crtsh_run)
        monkeypatch.setattr(ShodanModule, "is_configured", lambda self: True)
        monkeypatch.setattr(ShodanModule, "run", mock_shodan_run)
        monkeypatch.setattr(ShodanModule, "get_host_info", mock_shodan_get_host)
        monkeypatch.setattr(asyncio.get_event_loop(), "getaddrinfo", mock_getaddrinfo)

        result = await engine.scan("example.com", enabled_modules=["crtsh", "shodan"])

        # Must have retrofed both resolved subdomain IPs to Shodan
        assert "198.51.100.10" in shodan_retrofed_ips
        assert "198.51.100.20" in shodan_retrofed_ips
        assert len(shodan_retrofed_ips) == 2

        # Verify host mapping and associated assets
        assert len(result.hosts) == 2
        host_ips = {h.ip for h in result.hosts}
        assert "198.51.100.10" in host_ips
        assert "198.51.100.20" in host_ips

        api_host = next(h for h in result.hosts if h.ip == "198.51.100.10")
        assert "api.example.com" in api_host.hostnames
        assert any(p.port == 443 for p in api_host.ports)

    asyncio.run(_test())



