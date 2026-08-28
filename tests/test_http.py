"""Unit tests for AsyncHTTPClient."""

import asyncio
import httpx
from utils.http import AsyncHTTPClient


def test_http_client_get_json(monkeypatch):
    """Test get_json successfully fetches and parses JSON."""
    async def _test():
        client = AsyncHTTPClient()

        async def mock_get(self, *args, **kwargs):
            req = httpx.Request("GET", "https://api.example.com/data")
            return httpx.Response(200, json={"status": "ok", "count": 42}, request=req)

        monkeypatch.setattr(httpx.AsyncClient, "request", mock_get)

        data = await client.get_json("https://api.example.com/data")
        assert data == {"status": "ok", "count": 42}
        await client.close()

    asyncio.run(_test())


def test_http_client_handles_404(monkeypatch):
    """Test get_json returns None on 404 response."""
    async def _test():
        client = AsyncHTTPClient()

        async def mock_404(self, *args, **kwargs):
            req = httpx.Request("GET", "https://api.example.com/404")
            return httpx.Response(404, request=req)

        monkeypatch.setattr(httpx.AsyncClient, "request", mock_404)

        data = await client.get_json("https://api.example.com/404")
        assert data is None
        await client.close()

    asyncio.run(_test())


def test_http_client_shodan_rate_limiting():
    """Test that requests to shodan.io enforce the configured rate limit delay."""
    import time

    async def _test():
        client = AsyncHTTPClient()
        url = "https://api.shodan.io/api-info"

        t0 = time.monotonic()
        await client._enforce_domain_rate_limit(url)
        await client._enforce_domain_rate_limit(url)
        t1 = time.monotonic()

        # Elapsed time must be at least the configured shodan delay (~1.05s)
        assert (t1 - t0) >= 0.95
        await client.close()

    asyncio.run(_test())
