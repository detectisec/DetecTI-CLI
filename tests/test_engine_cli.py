"""Unit tests for ThreatTrack Engine and Typer CLI."""

import sys
from pathlib import Path
import pytest
from typer.testing import CliRunner

# Add the project root to sys.path to import the CLI module
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    # Import the CLI app from the detecti-cli file
    import importlib.util
    cli_path = Path(__file__).parent.parent / "detecti-cli"
    spec = importlib.util.spec_from_file_location("detecti_cli", cli_path)
    detecti_cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(detecti_cli)
    app = detecti_cli.app
except Exception as e:
    # Fallback for testing without CLI
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
    assert engine.classify_target("Villa11_Ext") == "file"
    assert engine.classify_target("org:google product:OpenSSH") == "query"


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


