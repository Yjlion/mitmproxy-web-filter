"""
Diagnostic / utility tool endpoints.

POST /api/tools/scan        — NSFW scan of an arbitrary URL.
POST /api/tools/youtube     — Parse a YouTube URL and fetch oEmbed metadata.
POST /api/tools/doh         — Query a DoH resolver for a domain.
GET  /api/tools/public-ip   — Discover the server's public IP address.
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

# Ensure the repo root is on sys.path so shared/ and proxy/ resolve.
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from fastapi import APIRouter, Body
from fastapi.responses import JSONResponse

router = APIRouter()
logger = logging.getLogger("webfilter.tools")

_PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
_SETTINGS_PATH = _PROJECT_ROOT / "config" / "settings.json"


def _load_settings():
    from shared.models import GlobalSettings
    if _SETTINGS_PATH.exists():
        return GlobalSettings.model_validate_json(
            _SETTINGS_PATH.read_text(encoding="utf-8-sig")
        )
    return GlobalSettings()


# ---------------------------------------------------------------------------
# POST /api/tools/scan
# ---------------------------------------------------------------------------

@router.post("/scan")
async def tools_scan(payload: dict = Body(...)):
    """Fetch a URL directly and classify it for NSFW content.

    Body fields
    -----------
    url             : str   — required
    text_threshold  : float — optional, default 0.80, clamped to [0, 1]
    image_threshold : float — optional, default 0.4,  clamped to [0, 1]
    max_images      : int   — optional, default 50,   clamped to [1, 100]
    """
    url = payload.get("url", "").strip()
    if not url:
        return JSONResponse({"detail": "url is required"}, status_code=400)

    text_threshold = float(payload.get("text_threshold", 0.80))
    image_threshold = float(payload.get("image_threshold", 0.4))
    max_images = int(payload.get("max_images", 50))

    # Clamp to sane ranges.
    text_threshold = max(0.0, min(1.0, text_threshold))
    image_threshold = max(0.0, min(1.0, image_threshold))
    max_images = max(1, min(100, max_images))

    from shared.nsfw_scan import scan_url
    result = await scan_url(
        url,
        text_threshold=text_threshold,
        image_threshold=image_threshold,
        max_images=max_images,
    )
    return result


# ---------------------------------------------------------------------------
# POST /api/tools/youtube
# ---------------------------------------------------------------------------

import re as _re

# Regexes for various YouTube URL forms.
_YT_VIDEO_RE = _re.compile(
    r"(?:youtube\.com/(?:watch\?(?:.*&)?v=|embed/|shorts/)|youtu\.be/)"
    r"([\w-]{11})"
)
_YT_CHANNEL_ID_RE = _re.compile(
    r"youtube\.com/channel/(UC[\w-]{22})"
)
_YT_HANDLE_RE = _re.compile(
    r"youtube\.com/(@[\w.\-]+)"
)
_YT_CUSTOM_RE = _re.compile(
    r"youtube\.com/(?:c|user)/([\w.\-]+)"
)


def _parse_youtube_url(url: str) -> dict:
    """Parse a YouTube URL and return kind / ids."""
    # Video forms: watch?v=, youtu.be/, /embed/, /shorts/
    m = _YT_VIDEO_RE.search(url)
    if m:
        return {"kind": "video", "video_id": m.group(1), "channel": None}

    # Channel ID
    m = _YT_CHANNEL_ID_RE.search(url)
    if m:
        return {"kind": "channel", "video_id": None, "channel": m.group(1)}

    # @handle
    m = _YT_HANDLE_RE.search(url)
    if m:
        return {"kind": "channel", "video_id": None, "channel": m.group(1)}

    # /c/... or /user/...
    m = _YT_CUSTOM_RE.search(url)
    if m:
        return {"kind": "channel", "video_id": None, "channel": m.group(1)}

    return {"kind": "unknown", "video_id": None, "channel": None}


@router.post("/youtube")
async def tools_youtube(payload: dict = Body(...)):
    """Parse a YouTube URL and, for video links, fetch oEmbed metadata.

    Body fields
    -----------
    url : str — required
    """
    import httpx

    url = payload.get("url", "").strip()
    if not url:
        return JSONResponse({"detail": "url is required"}, status_code=400)

    parsed = _parse_youtube_url(url)
    result: dict = dict(parsed, url=url)

    # Fetch oEmbed data for video links.
    if parsed["kind"] == "video":
        oembed_url = f"https://www.youtube.com/oembed?url={url}&format=json"
        try:
            async with httpx.AsyncClient(timeout=8.0, trust_env=False) as client:
                r = await client.get(oembed_url)
                r.raise_for_status()
                oembed = r.json()
            result["title"] = oembed.get("title")
            result["author_name"] = oembed.get("author_name")
            result["author_url"] = oembed.get("author_url")
            result["thumbnail_url"] = oembed.get("thumbnail_url")
        except Exception as exc:
            result["oembed_error"] = str(exc)

    return result


# ---------------------------------------------------------------------------
# POST /api/tools/doh
# ---------------------------------------------------------------------------

def _default_doh_server() -> str:
    """Return the DoH server from the first policy that has one, else Cloudflare."""
    for f in sorted((_PROJECT_ROOT / "policies").glob("*.json")):
        try:
            d = json.loads(f.read_text(encoding="utf-8-sig"))
            s = d.get("doh", {}).get("server", "").strip()
            if s:
                return s
        except Exception:
            pass
    return "https://1.1.1.3/dns-query"


@router.post("/doh")
async def tools_doh(payload: dict = Body(...)):
    """Query a DoH resolver for a domain and report whether it is blocked.

    Body fields
    -----------
    domain : str — required
    server : str — optional DoH endpoint URL (defaults to first policy server)
    """
    from proxy.addons.doh_filter import _DEPS_AVAILABLE, _resolve, _classify
    import dns.rdatatype
    import dns.rcode

    if not _DEPS_AVAILABLE:
        return JSONResponse(
            {"detail": "httpx and/or dnspython not installed; DoH tools unavailable"},
            status_code=503,
        )

    domain = payload.get("domain", "").strip()
    if not domain:
        return JSONResponse({"detail": "domain is required"}, status_code=400)

    server = (payload.get("server") or "").strip() or _default_doh_server()

    import asyncio
    results = await asyncio.gather(
        _resolve(domain, server, dns.rdatatype.A),
        _resolve(domain, server, dns.rdatatype.AAAA),
        return_exceptions=True,
    )

    messages = [m for m in results if not isinstance(m, Exception)]
    errors = [m for m in results if isinstance(m, Exception)]

    if not messages:
        err = errors[0]
        return JSONResponse(
            {
                "server": server,
                "domain": domain,
                "records": [],
                "blocked": False,
                "detail": f"query failed: {type(err).__name__}: {err}",
                "rcode": "SERVFAIL",
            }
        )

    blocked, detail, _ttl = _classify(messages)

    # Collect resource records.
    records: list[dict] = []
    for msg in messages:
        rcode_str = dns.rcode.to_text(msg.rcode())
        for rrset in msg.answer:
            rdtype_str = dns.rdatatype.to_text(rrset.rdtype)
            for rd in rrset:
                records.append({
                    "type": rdtype_str,
                    "name": str(rrset.name),
                    "ttl": rrset.ttl,
                    "data": getattr(rd, "address", rd.to_text()),
                })

    # Derive overall rcode from first response.
    rcode_str = dns.rcode.to_text(messages[0].rcode()) if messages else "NOERROR"

    return {
        "server": server,
        "domain": domain,
        "records": records,
        "blocked": blocked,
        "detail": detail,
        "rcode": rcode_str,
    }


# ---------------------------------------------------------------------------
# GET /api/tools/public-ip
# ---------------------------------------------------------------------------

@router.get("/public-ip")
async def tools_public_ip():
    """Discover the server's public IP address via an external service."""
    import httpx

    providers = [
        ("https://api.ipify.org?format=json", "json"),
        ("https://ifconfig.me/ip", "text"),
    ]

    for endpoint, fmt in providers:
        try:
            async with httpx.AsyncClient(timeout=5.0, trust_env=False) as client:
                r = await client.get(endpoint)
                r.raise_for_status()
                if fmt == "json":
                    return r.json()
                # Plain-text fallback (ifconfig.me)
                return {"ip": r.text.strip()}
        except Exception as exc:
            logger.debug("[tools] public-ip provider %s failed: %s", endpoint, exc)

    return JSONResponse({"error": "all public-ip providers failed"}, status_code=502)
