"""Tests for management/api/routes/tools.py endpoints.

Uses FastAPI TestClient (synchronous) so httpx must be mocked where the
endpoint itself makes outbound calls.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


def _make_client():
    """Return a TestClient for management.api.main.app."""
    from fastapi.testclient import TestClient
    import management.api.main as main_mod
    return TestClient(main_mod.app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# POST /api/tools/youtube — URL parsing
# ---------------------------------------------------------------------------

class TestYouTubeParsing:
    """Test all YouTube URL forms WITHOUT hitting the network (oEmbed mocked)."""

    def _oembed_mock(self, title="Test Video", author="Test Channel"):
        """Return a fake httpx.AsyncClient context manager that returns oEmbed JSON."""
        oembed_data = {
            "title": title,
            "author_name": author,
            "author_url": "https://www.youtube.com/@TestChannel",
            "thumbnail_url": "https://i.ytimg.com/vi/dQw4w9WgXcQ/hqdefault.jpg",
        }
        resp = MagicMock()
        resp.json = MagicMock(return_value=oembed_data)
        resp.raise_for_status = MagicMock()

        ctx = AsyncMock()
        ctx.__aenter__ = AsyncMock(return_value=ctx)
        ctx.__aexit__ = AsyncMock(return_value=False)
        ctx.get = AsyncMock(return_value=resp)
        return ctx

    def test_watch_url(self):
        client = _make_client()
        with patch("httpx.AsyncClient", return_value=self._oembed_mock()):
            resp = client.post(
                "/api/tools/youtube",
                json={"url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["kind"] == "video"
        assert data["video_id"] == "dQw4w9WgXcQ"
        assert data["title"] == "Test Video"
        assert data["author_name"] == "Test Channel"

    def test_short_url(self):
        client = _make_client()
        with patch("httpx.AsyncClient", return_value=self._oembed_mock()):
            resp = client.post(
                "/api/tools/youtube",
                json={"url": "https://youtu.be/dQw4w9WgXcQ"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["kind"] == "video"
        assert data["video_id"] == "dQw4w9WgXcQ"

    def test_shorts_url(self):
        client = _make_client()
        with patch("httpx.AsyncClient", return_value=self._oembed_mock()):
            resp = client.post(
                "/api/tools/youtube",
                json={"url": "https://www.youtube.com/shorts/dQw4w9WgXcQ"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["kind"] == "video"
        assert data["video_id"] == "dQw4w9WgXcQ"

    def test_embed_url(self):
        client = _make_client()
        with patch("httpx.AsyncClient", return_value=self._oembed_mock()):
            resp = client.post(
                "/api/tools/youtube",
                json={"url": "https://www.youtube.com/embed/dQw4w9WgXcQ"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["kind"] == "video"
        assert data["video_id"] == "dQw4w9WgXcQ"

    def test_channel_id_url(self):
        client = _make_client()
        resp = client.post(
            "/api/tools/youtube",
            json={"url": "https://www.youtube.com/channel/UCuAXFkgsw1L7xaCfnd5JJOw"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["kind"] == "channel"
        assert data["channel"] == "UCuAXFkgsw1L7xaCfnd5JJOw"

    def test_handle_url(self):
        client = _make_client()
        resp = client.post(
            "/api/tools/youtube",
            json={"url": "https://www.youtube.com/@MrBeast"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["kind"] == "channel"
        assert data["channel"] == "@MrBeast"

    def test_custom_c_url(self):
        client = _make_client()
        resp = client.post(
            "/api/tools/youtube",
            json={"url": "https://www.youtube.com/c/SomeChannel"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["kind"] == "channel"

    def test_user_url(self):
        client = _make_client()
        resp = client.post(
            "/api/tools/youtube",
            json={"url": "https://www.youtube.com/user/OldUser"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["kind"] == "channel"

    def test_unknown_url(self):
        client = _make_client()
        resp = client.post(
            "/api/tools/youtube",
            json={"url": "https://www.youtube.com/"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["kind"] == "unknown"

    def test_missing_url_returns_400(self):
        client = _make_client()
        resp = client.post("/api/tools/youtube", json={})
        assert resp.status_code == 400

    def test_oembed_failure_includes_error_key(self):
        """oEmbed failure must not crash; result should include oembed_error."""
        import httpx

        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(side_effect=httpx.ConnectError("refused"))
        ctx.__aexit__ = AsyncMock(return_value=False)

        client = _make_client()
        with patch("httpx.AsyncClient", return_value=ctx):
            resp = client.post(
                "/api/tools/youtube",
                json={"url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["kind"] == "video"
        assert "oembed_error" in data


# ---------------------------------------------------------------------------
# GET /api/tools/public-ip
# ---------------------------------------------------------------------------

class TestPublicIp:
    def _ip_mock(self, ip: str = "1.2.3.4"):
        resp = MagicMock()
        resp.json = MagicMock(return_value={"ip": ip})
        resp.text = ip
        resp.raise_for_status = MagicMock()

        ctx = AsyncMock()
        ctx.__aenter__ = AsyncMock(return_value=ctx)
        ctx.__aexit__ = AsyncMock(return_value=False)
        ctx.get = AsyncMock(return_value=resp)
        return ctx

    def test_returns_ip(self):
        client = _make_client()
        with patch("httpx.AsyncClient", return_value=self._ip_mock("8.8.8.8")):
            resp = client.get("/api/tools/public-ip")
        assert resp.status_code == 200
        data = resp.json()
        assert "ip" in data
        assert data["ip"] == "8.8.8.8"

    def test_all_providers_fail_returns_502(self):
        import httpx

        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(side_effect=httpx.ConnectError("refused"))
        ctx.__aexit__ = AsyncMock(return_value=False)

        client = _make_client()
        with patch("httpx.AsyncClient", return_value=ctx):
            resp = client.get("/api/tools/public-ip")
        assert resp.status_code == 502
        assert "error" in resp.json()


# ---------------------------------------------------------------------------
# POST /api/tools/scan — basic validation
# ---------------------------------------------------------------------------

class TestScanValidation:
    def test_missing_url_returns_400(self):
        client = _make_client()
        resp = client.post("/api/tools/scan", json={})
        assert resp.status_code == 400

    def test_thresholds_clamped(self):
        """Thresholds outside [0, 1] and max_images outside [1, 100] must be
        clamped (the scan itself is mocked to return quickly)."""
        async def _fake_scan(url, *, text_threshold, image_threshold, max_images, **kw):
            # Return the received params so we can verify clamping.
            return {
                "type": "other",
                "url": url,
                "content_type": "test/sentinel",
                "_text_threshold": text_threshold,
                "_image_threshold": image_threshold,
                "_max_images": max_images,
            }

        client = _make_client()
        # The endpoint does ``from shared.nsfw_scan import scan_url`` inside the
        # function body; patch the function on the shared module so any import
        # in the route picks up the mock.
        with patch("shared.nsfw_scan.scan_url", _fake_scan):
            resp = client.post(
                "/api/tools/scan",
                json={
                    "url": "https://example.com",
                    "text_threshold": -5.0,   # should clamp to 0.0
                    "image_threshold": 99.0,  # should clamp to 1.0
                    "max_images": 9999,       # should clamp to 100
                },
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["_text_threshold"] == 0.0
        assert data["_image_threshold"] == 1.0
        assert data["_max_images"] == 100
