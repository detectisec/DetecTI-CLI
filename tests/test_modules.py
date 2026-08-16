"""Unit tests for ThreatTrack collection and enrichment modules."""

import asyncio
from core.models import FindingType, SeverityLevel
from modules.censys import CensysModule
from modules.crtsh import CrtshModule
from modules.exploitdb import ExploitDBModule
from modules.nvd import NVDModule
from modules.reverse_whois import ReverseWhoisModule
from modules.shodan import ShodanModule
from utils.http import AsyncHTTPClient


def test_crtsh_module(monkeypatch):
    """Test crt.sh parsing of certificate transparency logs."""
    async def _test():
        module = CrtshModule()

        mock_crtsh_response = [
            {"name_value": "api.example.com\n*.admin.example.com"},
            {"name_value": "mail.example.com"},
        ]

        async def mock_get_json(self, url, params=None, timeout=None):
            return mock_crtsh_response

        monkeypatch.setattr(AsyncHTTPClient, "get_json", mock_get_json)

        findings = await module.run("example.com")
        subdomains = [f.value for f in findings]

        assert "api.example.com" in subdomains
        assert "admin.example.com" in subdomains
        assert "mail.example.com" in subdomains
        assert len(findings) == 3

    asyncio.run(_test())


def test_reverse_whois_module_fallback(monkeypatch):
    """Test reverse WHOIS free fallback parsing."""
    async def _test():
        module = ReverseWhoisModule()

        class MockResponse:
            status_code = 200
            text = "site1.org\nsite2.org\n"

        async def mock_get(self, url, params=None, timeout=None, raise_for_status=True):
            return MockResponse()

        monkeypatch.setattr(AsyncHTTPClient, "get", mock_get)

        findings = await module.run("1.2.3.4")
        domains = [f.value for f in findings]

        assert "site1.org" in domains
        assert "site2.org" in domains
        assert len(findings) == 2

    asyncio.run(_test())


def test_nvd_module_enrichment(monkeypatch):
    """Test NVD + EPSS + CISA KEV full enrichment."""
    async def _test():
        module = NVDModule()

        mock_nvd_data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-44228",
                        "descriptions": [{"lang": "en", "value": "Log4j RCE vulnerability"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 10.0,
                                        "baseSeverity": "CRITICAL",
                                    }
                                }
                            ]
                        },
                        "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}],
                    }
                }
            ]
        }

        mock_epss_data = {
            "data": [{"cve": "CVE-2021-44228", "epss": "0.9754", "percentile": "0.9999", "date": "2024-01-01"}]
        }

        mock_cisa_data = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-44228",
                    "vendorProject": "Apache",
                    "product": "Log4j",
                    "vulnerabilityName": "Log4j Remote Code Execution",
                    "dateAdded": "2021-12-10",
                    "dueDate": "2021-12-24",
                    "requiredAction": "Apply updates",
                }
            ]
        }

        async def mock_get_json(self, url, headers=None, params=None, timeout=None):
            if "cisa.gov" in url:
                return mock_cisa_data
            elif "api.first.org" in url:
                return mock_epss_data
            elif "services.nvd.nist.gov" in url:
                return mock_nvd_data
            return None

        monkeypatch.setattr(AsyncHTTPClient, "get_json", mock_get_json)

        vuln_data = await module.enrich_cve("CVE-2021-44228")

        assert vuln_data.cve_id == "CVE-2021-44228"
        assert vuln_data.cvss_score == 10.0
        assert vuln_data.cvss_severity == SeverityLevel.CRITICAL
        assert vuln_data.epss is not None
        assert vuln_data.epss.epss_score == 0.9754
        assert vuln_data.cisa_kev is not None
        assert vuln_data.cisa_kev.in_cisa_kev is True
        assert vuln_data.cisa_kev.vendor_project == "Apache"

    asyncio.run(_test())


def test_exploitdb_module(monkeypatch):
    """Test ExploitDB and GitHub PoC retrieval."""
    async def _test():
        module = ExploitDBModule()

        monkeypatch.setattr("cve_searchsploit.edbid_from_cve", lambda cve: ["50592"])

        mock_poc_data = {
            "pocs": [
                {
                    "name": "log4j-poc",
                    "html_url": "https://github.com/test/log4j-poc",
                    "owner": {"login": "test"},
                }
            ]
        }

        async def mock_get_json(self, url, params=None, timeout=None):
            return mock_poc_data

        monkeypatch.setattr(AsyncHTTPClient, "get_json", mock_get_json)

        exploits = await module.get_exploits_for_cve("CVE-2021-44228")
        assert len(exploits) >= 2
        sources = [e.source for e in exploits]
        assert "ExploitDB" in sources
        assert "GitHub" in sources

    asyncio.run(_test())


def test_censys_module(monkeypatch):
    """Test Censys Platform API v3 host lookup and result parsing."""
    async def _test():
        valid_org_uuid = "12345678-1234-5678-1234-567812345678"
        monkeypatch.setattr("config.settings.censys_pat_token", "test-pat-token-12345")
        monkeypatch.setattr("config.settings.censys_org_id", valid_org_uuid)

        module = CensysModule()
        assert module.is_configured() is True

        headers = module._get_auth_headers()
        assert headers["Authorization"] == "Bearer test-pat-token-12345"
        assert headers["X-Organization-ID"] == valid_org_uuid

        # Test that invalid org id is ignored (preventing Censys 422 error)
        module_invalid_org = CensysModule(pat_token="test-pat", org_id="invalid-not-uuid")
        headers_invalid = module_invalid_org._get_auth_headers()
        assert "X-Organization-ID" not in headers_invalid

        mock_censys_data = {
            "code": 200,
            "status": "OK",
            "result": {
                "ip": "1.1.1.1",
                "location": {
                    "country": "Australia",
                    "country_code": "AU",
                    "city": "Brisbane",
                    "province": "Queensland",
                },
                "autonomous_system": {
                    "asn": 13335,
                    "name": "Cloudflare, Inc.",
                    "description": "CLOUDFLARENET",
                },
                "operating_system": {
                    "product": "Linux",
                },
                "dns": {
                    "names": ["one.one.one.one"],
                    "reverse_dns": {"names": ["one.one.one.one"]},
                },
                "services": [
                    {
                        "port": 80,
                        "service_name": "HTTP",
                        "transport_protocol": "TCP",
                        "banner": "Cloudflare HTTP",
                    },
                    {
                        "port": 443,
                        "service_name": "HTTPS",
                        "transport_protocol": "TCP",
                        "tls": {
                            "certificate": {
                                "names": ["cloudflare.com", "*.cloudflare.com"]
                            }
                        },
                        "vulnerabilities": [
                            {"cve": "CVE-2023-1234"}
                        ],
                    },
                ],
            },
        }

        class MockResponse:
            status_code = 200
            def json(self):
                return mock_censys_data

        async def mock_get(self, url, headers=None, params=None, timeout=None, raise_for_status=True):
            assert "1.1.1.1" in url
            assert "Bearer test-pat-token-12345" in headers.get("Authorization", "")
            return MockResponse()

        monkeypatch.setattr(AsyncHTTPClient, "get", mock_get)

        findings = await module.run("1.1.1.1")
        assert len(findings) > 0

        types = [f.type for f in findings]
        assert FindingType.HOST_INFO in types
        assert FindingType.OPEN_PORT in types
        assert FindingType.SUBDOMAIN in types
        assert FindingType.VULNERABILITY in types

        host_info_findings = [f for f in findings if f.type == FindingType.HOST_INFO]
        assert len(host_info_findings) == 1
        assert host_info_findings[0].host_info.ip == "1.1.1.1"
        assert host_info_findings[0].host_info.asn == "AS13335"
        assert host_info_findings[0].host_info.country_name == "Australia"
        assert host_info_findings[0].host_info.ports == [80, 443]
        assert "CVE-2023-1234" in host_info_findings[0].host_info.vulns

    asyncio.run(_test())


def test_censys_module_cenql_search(monkeypatch):
    """Test Censys CenQL search query execution and routing."""
    async def _test():
        module = CensysModule(pat_token="censys_pat_secret")
        assert module.is_configured() is True

        captured_requests = []

        mock_search_data = {
            "code": 200,
            "status": "OK",
            "result": {
                "query": "ip: 192.168.1.0/24",
                "total": 1,
                "hits": [
                    {
                        "ip": "192.168.1.10",
                        "location": {"country": "Brazil", "country_code": "BR", "city": "Sao Paulo"},
                        "autonomous_system": {"asn": 28573, "name": "Claro"},
                        "services": [
                            {"port": 443, "service_name": "HTTPS", "transport_protocol": "TCP"}
                        ],
                    }
                ],
                "links": {},
            },
        }

        class MockResponse:
            status_code = 200
            def json(self):
                return mock_search_data

        async def mock_post(self, url, headers=None, params=None, json=None, data=None, timeout=None, raise_for_status=True):
            captured_requests.append({"url": url, "json": json, "headers": headers})
            return MockResponse()

        monkeypatch.setattr(AsyncHTTPClient, "post", mock_post)

        # Test CIDR routing to CenQL search query
        findings = await module.run("192.168.1.0/24")
        assert len(captured_requests) == 1
        assert captured_requests[0]["json"]["query"] == "ip: 192.168.1.0/24"
        assert len(findings) > 0
        assert any(f.type == FindingType.OPEN_PORT for f in findings)

        # Test Domain routing to CenQL names query
        await module.run("example.com")
        assert len(captured_requests) == 2
        assert captured_requests[1]["json"]["query"] == "names: example.com"

    asyncio.run(_test())


def test_censys_platform_client(monkeypatch):
    """Test CensysPlatformClient synchronous reference implementation and exception handling."""
    import pytest
    from modules.censys import CensysPlatformClient, CensysAuthError, CensysRateLimitError, CensysAPIError

    valid_uuid = "12345678-1234-5678-1234-567812345678"
    client = CensysPlatformClient(pat_token="mock_pat_token", org_id=valid_uuid)
    assert client.session.headers["Authorization"] == "Bearer mock_pat_token"
    assert client.session.headers["X-Organization-ID"] == valid_uuid

    # 1. Test get_host success
    class MockResponse200:
        status_code = 200
        text = '{"code": 200, "result": {"ip": "8.8.8.8"}}'
        def json(self):
            return {"code": 200, "result": {"ip": "8.8.8.8"}}

    monkeypatch.setattr(client.session, "request", lambda method, url, **kwargs: MockResponse200())
    res = client.get_host("8.8.8.8")
    assert res["result"]["ip"] == "8.8.8.8"

    # 2. Test search_query
    res_search = client.search_query("services.port: 443", page_size=10)
    assert res_search["result"]["ip"] == "8.8.8.8"

    # 3. Test aggregate_search
    res_agg = client.aggregate_search("services.port: 80", field="location.country_code")
    assert res_agg["result"]["ip"] == "8.8.8.8"

    # 4. Test get_certificate
    res_cert = client.get_certificate("abc123sha256fingerprint")
    assert res_cert["result"]["ip"] == "8.8.8.8"

    # 5. Test convert_legacy_query
    res_conv = client.convert_legacy_query("80.http.get.title: test")
    assert res_conv["result"]["ip"] == "8.8.8.8"

    # 6. Test 401/403 Auth Error
    class MockResponse401:
        status_code = 401
        text = "Invalid PAT Token"

    monkeypatch.setattr(client.session, "request", lambda method, url, **kwargs: MockResponse401())
    with pytest.raises(CensysAuthError):
        client.get_host("8.8.8.8")

    # 7. Test 429 Rate Limit Error
    class MockResponse429:
        status_code = 429
        text = "Rate limit exceeded"

    monkeypatch.setattr(client.session, "request", lambda method, url, **kwargs: MockResponse429())
    with pytest.raises(CensysRateLimitError):
        client.get_host("8.8.8.8")

    # 8. Test 422 CenQL Syntax Error
    class MockResponse422:
        status_code = 422
        text = "Unprocessable query syntax"

    monkeypatch.setattr(client.session, "request", lambda method, url, **kwargs: MockResponse422())
    with pytest.raises(CensysAPIError):
        client.search_query("invalid:::cenql")


def test_shodan_search_pagination(monkeypatch):
    """Test Shodan multi-page search pagination retrieving all 200 IPs across pages."""
    async def _test():
        monkeypatch.setattr("config.settings.shodan_api_key", "mock-shodan-key")
        module = ShodanModule()

        page1_ips = [f"10.0.0.{i}" for i in range(1, 101)]
        page2_ips = [f"10.0.1.{i}" for i in range(1, 101)]

        async def mock_get_json(self, url, params=None, timeout=None):
            if "host/search" in url:
                page = params.get("page", 1)
                if page == 1:
                    return {
                        "total": 200,
                        "matches": [{"ip_str": ip, "port": 80} for ip in page1_ips],
                    }
                elif page == 2:
                    return {
                        "total": 200,
                        "matches": [{"ip_str": ip, "port": 80} for ip in page2_ips],
                    }
                return {"total": 200, "matches": []}
            elif "shodan/host/" in url:
                ip = url.split("/")[-1]
                return {
                    "ip_str": ip,
                    "hostnames": [],
                    "domains": [],
                    "ports": [80],
                    "data": [{"port": 80, "product": "nginx"}],
                }
            return None

        monkeypatch.setattr(AsyncHTTPClient, "get_json", mock_get_json)

        findings = await module.search_query("org:TestOrg")
        discovered_ips = {f.host_ip for f in findings if f.host_ip}
        assert len(discovered_ips) == 200
        assert "10.0.0.1" in discovered_ips
        assert "10.0.1.100" in discovered_ips

    asyncio.run(_test())


def test_censys_search_pagination_cursor(monkeypatch):
    """Test Censys CenQL search pagination using cursor over multiple pages."""
    async def _test():
        module = CensysModule(pat_token="censys_pat_mock")

        page1_hits = [{"ip": f"192.168.0.{i}", "services": [{"port": 443, "service_name": "HTTPS"}]} for i in range(1, 101)]
        page2_hits = [{"ip": f"192.168.1.{i}", "services": [{"port": 443, "service_name": "HTTPS"}]} for i in range(1, 101)]

        requested_cursors = []

        class MockResponse:
            def __init__(self, data):
                self.status_code = 200
                self._data = data
            def json(self):
                return self._data

        async def mock_post(self, url, headers=None, params=None, json=None, data=None, timeout=None, raise_for_status=True):
            cursor = json.get("cursor") if json else None
            requested_cursors.append(cursor)
            if not cursor:
                return MockResponse({
                    "code": 200,
                    "result": {
                        "total": 200,
                        "hits": page1_hits,
                        "links": {"next": "cursor_page_2_token"},
                    },
                })
            elif cursor == "cursor_page_2_token":
                return MockResponse({
                    "code": 200,
                    "result": {
                        "total": 200,
                        "hits": page2_hits,
                        "links": {"next": None},
                    },
                })
            return MockResponse({"code": 200, "result": {"hits": [], "links": {}}})

        monkeypatch.setattr(AsyncHTTPClient, "post", mock_post)

        findings = await module.search_query("services.port: 443")
        discovered_ips = {f.host_ip for f in findings if f.host_ip}
        assert len(discovered_ips) == 200
        assert "192.168.0.1" in discovered_ips
        assert "192.168.1.100" in discovered_ips
        assert requested_cursors == [None, "cursor_page_2_token"]

    asyncio.run(_test())




