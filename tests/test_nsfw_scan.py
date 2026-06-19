"""Tests for shared/nsfw_scan.py.

All network calls and ML classifiers are monkeypatched so these tests run
offline without a proxy and without the NudeNet model.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import shared.nsfw_scan as ns


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(
    content: bytes,
    content_type: str,
    url: str = "https://example.com/",
    status_code: int = 200,
) -> MagicMock:
    """Build a mock httpx.Response-like object."""
    resp = MagicMock()
    resp.content = content
    resp.headers = {"content-type": content_type}
    resp.status_code = status_code
    resp.text = content.decode("utf-8", errors="replace")
    return resp


def _run(coro):
    """Run a coroutine in a fresh event loop (compatible with Python 3.14+)."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _make_client_ctx(get_fn):
    """Return a MagicMock that behaves as ``async with httpx.AsyncClient(...) as client:``
    where ``client.get`` is replaced by *get_fn* (an async callable)."""
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=ctx)
    ctx.__aexit__ = AsyncMock(return_value=False)
    ctx.get = get_fn
    return ctx


# ---------------------------------------------------------------------------
# Tests: image/* branch
# ---------------------------------------------------------------------------

class TestImageBranch:
    def test_image_clean(self, monkeypatch):
        """image/* URL, detector says clean."""
        img_bytes = b"\xff\xd8\xff" + b"\x00" * 2048  # fake JPEG, > 1 KB
        resp = _make_response(img_bytes, "image/jpeg", "https://example.com/photo.jpg")

        monkeypatch.setattr(ns, "_is_nsfw", lambda body, thr: (False, []))
        monkeypatch.setattr(ns, "_too_small", lambda body, dim: False)

        ctx = _make_client_ctx(AsyncMock(return_value=resp))
        with patch("httpx.AsyncClient", return_value=ctx):
            result = _run(ns.scan_url("https://example.com/photo.jpg", image_threshold=0.4))

        assert result["type"] == "image"
        assert result["nsfw"] is False
        assert result["image_threshold"] == 0.4
        assert "detections" in result

    def test_image_nsfw(self, monkeypatch):
        """image/* URL, detector flags NSFW."""
        img_bytes = b"\xff\xd8\xff" + b"\x00" * 2048
        resp = _make_response(img_bytes, "image/jpeg")

        fake_det = [{"class": "FEMALE_BREAST_EXPOSED", "score": 0.9}]
        monkeypatch.setattr(ns, "_is_nsfw", lambda body, thr: (True, fake_det))
        monkeypatch.setattr(ns, "_too_small", lambda body, dim: False)

        ctx = _make_client_ctx(AsyncMock(return_value=resp))
        with patch("httpx.AsyncClient", return_value=ctx):
            result = _run(ns.scan_url("https://example.com/nsfw.jpg"))

        assert result["type"] == "image"
        assert result["nsfw"] is True
        assert result["detections"] == fake_det

    def test_image_too_small_skipped(self, monkeypatch):
        """Images that are too small must be skipped (nsfw=False, skipped key present)."""
        img_bytes = b"\xff\xd8\xff" + b"\x00" * 2048
        resp = _make_response(img_bytes, "image/png")

        monkeypatch.setattr(ns, "_too_small", lambda body, dim: True)
        monkeypatch.setattr(ns, "_is_nsfw", lambda body, thr: (True, []))  # would be nsfw

        ctx = _make_client_ctx(AsyncMock(return_value=resp))
        with patch("httpx.AsyncClient", return_value=ctx):
            result = _run(ns.scan_url("https://example.com/tiny.png"))

        assert result["type"] == "image"
        assert result["nsfw"] is False
        assert result.get("skipped") == "too_small"


# ---------------------------------------------------------------------------
# Tests: text/html branch
# ---------------------------------------------------------------------------

_SIMPLE_HTML = b"""
<html>
<body>
  <p>Hello world</p>
  <img src="/a.jpg" />
  <img src="https://cdn.example.com/b.jpg" />
</body>
</html>
"""

_HTML_MANY_IMGS = (
    b"<html><body>"
    + b"".join(f'<img src="/img{i}.jpg" />'.encode() for i in range(60))
    + b"</body></html>"
)

_IMG_BYTES = b"\xff\xd8\xff" + b"\x00" * 2048  # fake JPEG > 1 KB


class TestPageBranch:
    def _patch_text_classifiers(self, monkeypatch, keyword_score=0.0, nsfw=False):
        monkeypatch.setattr(ns, "_load_ml_model", lambda: None)
        monkeypatch.setattr(ns, "_keyword_score", lambda text: keyword_score)
        monkeypatch.setattr(ns, "_classify", lambda text, thr: nsfw)

    def _patch_image_classifier(self, monkeypatch, img_nsfw=False, detections=None):
        dets = detections or []
        monkeypatch.setattr(ns, "_is_nsfw", lambda body, thr: (img_nsfw, dets))
        monkeypatch.setattr(ns, "_too_small", lambda body, dim: False)

    def test_html_page_clean(self, monkeypatch):
        """HTML page with two images, all clean."""
        page_resp = _make_response(_SIMPLE_HTML, "text/html", "https://example.com/")
        img_resp = _make_response(_IMG_BYTES, "image/jpeg")

        self._patch_text_classifiers(monkeypatch)
        self._patch_image_classifier(monkeypatch)

        call_count = [0]

        async def _get(url, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return page_resp
            return img_resp

        ctx = _make_client_ctx(_get)
        with patch("httpx.AsyncClient", return_value=ctx):
            result = _run(ns.scan_url("https://example.com/"))

        assert result["type"] == "page"
        assert result["text"]["nsfw"] is False
        assert result["text"]["keyword_score"] == 0.0
        assert result["text"]["threshold"] == 0.80
        assert len(result["images"]) == 2
        assert result["image_threshold"] == 0.4
        assert all(not img["nsfw"] for img in result["images"])

    def test_html_page_nsfw_text(self, monkeypatch):
        """HTML page where text classifier flags NSFW."""
        page_resp = _make_response(_SIMPLE_HTML, "text/html")
        img_resp = _make_response(_IMG_BYTES, "image/jpeg")

        self._patch_text_classifiers(monkeypatch, keyword_score=1.0, nsfw=True)
        self._patch_image_classifier(monkeypatch)

        call_count = [0]

        async def _get(url, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return page_resp
            return img_resp

        ctx = _make_client_ctx(_get)
        with patch("httpx.AsyncClient", return_value=ctx):
            result = _run(ns.scan_url("https://example.com/"))

        assert result["type"] == "page"
        assert result["text"]["nsfw"] is True

    def test_relative_url_resolution(self, monkeypatch):
        """Relative <img src="/a.jpg"> must be resolved against the page URL."""
        page_resp = _make_response(_SIMPLE_HTML, "text/html")
        img_resp = _make_response(_IMG_BYTES, "image/jpeg")

        self._patch_text_classifiers(monkeypatch)
        self._patch_image_classifier(monkeypatch)

        fetched_urls: list[str] = []
        call_count = [0]

        async def _get(url, **kwargs):
            call_count[0] += 1
            fetched_urls.append(url)
            if call_count[0] == 1:
                return page_resp
            return img_resp

        ctx = _make_client_ctx(_get)
        with patch("httpx.AsyncClient", return_value=ctx):
            _run(ns.scan_url("https://example.com/"))

        # /a.jpg should be resolved to https://example.com/a.jpg
        abs_fetched = [u for u in fetched_urls if "a.jpg" in u or "b.jpg" in u]
        assert any("example.com/a.jpg" in u for u in abs_fetched), fetched_urls
        assert any("cdn.example.com/b.jpg" in u for u in abs_fetched), fetched_urls

    def test_max_images_cap(self, monkeypatch):
        """Only max_images images must be fetched, even if the page has more."""
        page_resp = _make_response(_HTML_MANY_IMGS, "text/html")
        img_resp = _make_response(_IMG_BYTES, "image/jpeg")

        self._patch_text_classifiers(monkeypatch)
        self._patch_image_classifier(monkeypatch)

        call_count = [0]

        async def _get(url, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return page_resp
            return img_resp

        ctx = _make_client_ctx(_get)
        # The HTML has 60 img tags; we cap at 5.
        with patch("httpx.AsyncClient", return_value=ctx):
            result = _run(ns.scan_url("https://example.com/", max_images=5))

        assert len(result["images"]) == 5

    def test_fetch_error_returns_error_type(self, monkeypatch):
        """A fetch failure must produce type=error."""
        import httpx

        # Raise on construction (not inside the context), i.e. the async with enter raises.
        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(side_effect=httpx.ConnectError("refused"))
        ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = _run(ns.scan_url("https://unreachable.example.com/"))

        assert result["type"] == "error"
        assert "error" in result


# ---------------------------------------------------------------------------
# Tests: other content type
# ---------------------------------------------------------------------------

class TestOtherBranch:
    def test_pdf_content_type(self, monkeypatch):
        resp = _make_response(b"%PDF-1.4", "application/pdf")
        ctx = _make_client_ctx(AsyncMock(return_value=resp))

        with patch("httpx.AsyncClient", return_value=ctx):
            result = _run(ns.scan_url("https://example.com/doc.pdf"))

        assert result["type"] == "other"
        assert result["content_type"] == "application/pdf"
