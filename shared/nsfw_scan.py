"""
On-demand NSFW scanner for arbitrary URLs.

Fetches a URL directly (bypassing any proxy) and classifies it:

* ``image/*``  — runs the NudeNet image classifier.
* ``text/html`` — runs the keyword/ML text classifier on the page text, then
  extracts ``<img>`` tags, fetches them concurrently (bounded), and classifies
  each with NudeNet.
* anything else — returns a short descriptor without classification.

Public entry points
-------------------
``scan_url(url, ...)``        — async coroutine; ``await`` it from async code.
``scan_url_sync(url, ...)``   — thin sync wrapper via ``asyncio.run``; use from
                                CLI / non-async contexts.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any
from urllib.parse import urljoin

logger = logging.getLogger("webfilter.nsfw_scan")

# ---------------------------------------------------------------------------
# Helpers re-used from proxy addons (mitmproxy is installed in the venv).
# ---------------------------------------------------------------------------

from proxy.addons.image_classifier import _is_nsfw, _too_small, _MIN_IMAGE_BYTES
from proxy.addons.text_classifier import (
    _load_ml_model,
    _strip_html,
    _keyword_score,
    _classify,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_TEXT_THRESHOLD: float = 0.80
_DEFAULT_IMAGE_THRESHOLD: float = 0.4
_DEFAULT_MAX_IMAGES: int = 50
_DEFAULT_TIMEOUT: float = 10.0

# Minimum dimension (px) for images sent to the classifier.
# Mirrors the proxy addon default (ImageClassifierConfig.min_dimension = 100).
_MIN_DIMENSION: int = 100

# Maximum concurrent image fetches to avoid overwhelming the target server.
_IMAGE_CONCURRENCY: int = 8

# User-Agent used when fetching; neutral enough to get real content.
_UA = "Mozilla/5.0 (compatible; WebFilter-Scanner/1.0)"


# ---------------------------------------------------------------------------
# Image-URL extraction
# ---------------------------------------------------------------------------

def _extract_image_urls(html: str, base_url: str, max_images: int) -> list[str]:
    """Return up to *max_images* absolute image URLs from *html*."""
    # Try BeautifulSoup first (more robust), fall back to regex.
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
        srcs: list[str] = []
        for tag in soup.find_all("img"):
            src = tag.get("src") or tag.get("data-src") or ""
            if src:
                srcs.append(src)
    except ImportError:
        srcs = re.findall(r'<img[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)

    # Resolve relative URLs, deduplicate while preserving order.
    seen: set[str] = set()
    result: list[str] = []
    for src in srcs:
        abs_url = urljoin(base_url, src.strip())
        if abs_url not in seen:
            seen.add(abs_url)
            result.append(abs_url)
        if len(result) >= max_images:
            break
    return result


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------

async def scan_url(
    url: str,
    *,
    text_threshold: float = _DEFAULT_TEXT_THRESHOLD,
    image_threshold: float = _DEFAULT_IMAGE_THRESHOLD,
    max_images: int = _DEFAULT_MAX_IMAGES,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Fetch *url* and classify its content for NSFW material.

    Parameters
    ----------
    url:
        The URL to fetch and classify.
    text_threshold:
        ML confidence threshold for the text classifier (0.0–1.0).
    image_threshold:
        NudeNet score threshold for image classification (0.0–1.0).
    max_images:
        Maximum number of ``<img>`` tags to classify on an HTML page.
    timeout:
        HTTP request timeout in seconds.

    Returns
    -------
    dict
        * ``{"type": "image", ...}`` for ``image/*`` responses.
        * ``{"type": "page", ...}``  for ``text/html`` responses.
        * ``{"type": "other", ...}`` for any other content type.
        * ``{"type": "error", ...}`` on fetch/parse failure.
    """
    import httpx

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            trust_env=False,          # never route through the system proxy
            follow_redirects=True,
            headers={"User-Agent": _UA},
        ) as client:
            resp = await client.get(url)
    except Exception as exc:
        logger.warning("[nsfw_scan] fetch error for %s: %s", url, exc)
        return {"type": "error", "url": url, "error": str(exc)}

    ct = resp.headers.get("content-type", "").split(";")[0].strip().lower()

    # ------------------------------------------------------------------
    # image/* — classify the image body directly
    # ------------------------------------------------------------------
    if ct.startswith("image/"):
        body = resp.content
        if len(body) < _MIN_IMAGE_BYTES or _too_small(body, _MIN_DIMENSION):
            return {
                "type": "image",
                "url": url,
                "nsfw": False,
                "detections": [],
                "image_threshold": image_threshold,
                "skipped": "too_small",
            }
        nsfw, detections = _is_nsfw(body, image_threshold)
        return {
            "type": "image",
            "url": url,
            "nsfw": nsfw,
            "detections": detections,
            "image_threshold": image_threshold,
        }

    # ------------------------------------------------------------------
    # text/html — classify page text + embedded images
    # ------------------------------------------------------------------
    if ct == "text/html":
        try:
            html = resp.text
        except Exception as exc:
            return {"type": "error", "url": url, "error": f"decode error: {exc}"}

        # Text classification
        _load_ml_model()
        text = _strip_html(html)
        kw_score = _keyword_score(text)
        text_nsfw = _classify(text, text_threshold)

        # Image URL extraction
        img_urls = _extract_image_urls(html, url, max_images)
        image_results = await _classify_images_concurrently(
            img_urls, image_threshold, timeout=timeout
        )

        return {
            "type": "page",
            "url": url,
            "text": {
                "nsfw": text_nsfw,
                "keyword_score": kw_score,
                "threshold": text_threshold,
            },
            "images": image_results,
            "image_threshold": image_threshold,
        }

    # ------------------------------------------------------------------
    # Anything else — report the content type without classifying
    # ------------------------------------------------------------------
    return {"type": "other", "url": url, "content_type": ct}


async def _classify_images_concurrently(
    img_urls: list[str],
    image_threshold: float,
    *,
    timeout: float,
) -> list[dict[str, Any]]:
    """Fetch and classify each image URL concurrently, bounded by a semaphore."""
    sem = asyncio.Semaphore(_IMAGE_CONCURRENCY)

    import httpx

    async def _classify_one(img_url: str) -> dict[str, Any]:
        async with sem:
            try:
                async with httpx.AsyncClient(
                    timeout=timeout,
                    trust_env=False,
                    follow_redirects=True,
                    headers={"User-Agent": _UA},
                ) as client:
                    r = await client.get(img_url)
                body = r.content
            except Exception as exc:
                return {"url": img_url, "nsfw": False, "detections": [], "error": str(exc)}

            if len(body) < _MIN_IMAGE_BYTES or _too_small(body, _MIN_DIMENSION):
                return {"url": img_url, "nsfw": False, "detections": [], "error": None, "skipped": "too_small"}

            try:
                nsfw, detections = _is_nsfw(body, image_threshold)
                return {"url": img_url, "nsfw": nsfw, "detections": detections, "error": None}
            except Exception as exc:
                return {"url": img_url, "nsfw": False, "detections": [], "error": str(exc)}

    results = await asyncio.gather(*(_classify_one(u) for u in img_urls))
    return list(results)


# ---------------------------------------------------------------------------
# Sync wrapper for CLI / non-async contexts
# ---------------------------------------------------------------------------

def scan_url_sync(
    url: str,
    *,
    text_threshold: float = _DEFAULT_TEXT_THRESHOLD,
    image_threshold: float = _DEFAULT_IMAGE_THRESHOLD,
    max_images: int = _DEFAULT_MAX_IMAGES,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Synchronous wrapper around :func:`scan_url`.

    Suitable for use in CLI scripts and other non-async code.
    """
    return asyncio.run(
        scan_url(
            url,
            text_threshold=text_threshold,
            image_threshold=image_threshold,
            max_images=max_images,
            timeout=timeout,
        )
    )
