"""
YouTube channel filter.

Blocks/allows videos by channel. A channel can be listed three ways in the
policy's `channels` list — all are matched:
  * Channel ID:  UCxxxxxxxxxxxxxxxxxxxxxx
  * @handle:     @MrBeast   (or just MrBeast)
  * Display name: MrBeast   (case-insensitive)

Two interception points are needed because youtube.com is a single-page app:
  1. The InnerTube player API (/youtubei/v1/player) — JSON, fires on every video
     navigation *without* a page reload. We rewrite playabilityStatus to ERROR
     so the player refuses to play. This is the case that previously slipped
     through ("video plays, only blocks on reload").
  2. The watch page HTML (/watch) — fires on direct loads and full reloads.
"""
from __future__ import annotations
import json
import re
from mitmproxy import http
from proxy.block_page import make_block_response, log_block

_YOUTUBE_HOSTS = {
    "www.youtube.com", "youtube.com", "m.youtube.com",
    "youtubei.googleapis.com",
}
_PLAYER_PATH = "/youtubei/v1/player"

# HTML extraction
_CHANNEL_ID_RE = re.compile(r'"channelId":"(UC[\w-]{22})"')
_AUTHOR_RE = re.compile(r'"author":"((?:[^"\\]|\\.)*)"')
_HANDLE_RE = re.compile(r'"canonicalBaseUrl":"/(@[\w.\-]+)"')
_OWNER_URL_HANDLE_RE = re.compile(r'/(@[\w.\-]+)')


def _is_youtube(host: str) -> bool:
    return host in _YOUTUBE_HOSTS


def _should_filter(host: str, cfg) -> bool:
    if cfg.include_only:
        return any(host == s or host.endswith("." + s) for s in cfg.include_only)
    if cfg.exclude:
        return not any(host == s or host.endswith("." + s) for s in cfg.exclude)
    return True


def _norm_name(s: str) -> str:
    return s.strip().lstrip("@").lower()


def _json_unescape(raw: str) -> str:
    """Decode a JSON-escaped string fragment (e.g. \\u0026, \\")."""
    try:
        return json.loads(f'"{raw}"')
    except Exception:
        return raw


def _channel_listed(channel_id: str | None, author: str | None,
                    handle: str | None, channels: list[str]) -> bool:
    """True if this video's channel appears in the configured list, matched by
    channel ID, display name, or @handle (all case-insensitive for names)."""
    ids = {channel_id} if channel_id else set()
    names = set()
    if author:
        names.add(author.lower())
    if handle:
        names.add(_norm_name(handle))

    for entry in channels:
        e = entry.strip()
        if not e:
            continue
        if e in ids:
            return True
        if _norm_name(e) in names:
            return True
    return False


def _is_blocked(channel_id, author, handle, cfg) -> bool:
    listed = _channel_listed(channel_id, author, handle, cfg.channels)
    if cfg.mode == "whitelist":
        return not listed
    return listed  # blacklist


class YouTubeFilter:
    def response(self, flow: http.HTTPFlow) -> None:
        if flow.metadata.get("url_allowed") or flow.metadata.get("mitm_passthrough"):
            return

        policy = flow.metadata.get("policy")
        if not policy or not policy.youtube.enabled:
            return

        host = flow.request.pretty_host
        if not _is_youtube(host) or not _should_filter(host, policy.youtube):
            return

        if not flow.response:
            return

        path = flow.request.path
        if _PLAYER_PATH in path:
            self._handle_player(flow, policy)
        elif "/watch" in path:
            self._handle_watch_html(flow, policy)

    # --- InnerTube player API (SPA navigation) ---------------------------------
    def _handle_player(self, flow: http.HTTPFlow, policy) -> None:
        ct = flow.response.headers.get("content-type", "")
        if "json" not in ct:
            return
        try:
            data = json.loads(flow.response.text)
        except Exception:
            return

        vd = data.get("videoDetails", {}) or {}
        micro = (data.get("microformat", {}) or {}).get("playerMicroformatRenderer", {}) or {}

        channel_id = vd.get("channelId") or micro.get("externalChannelId")
        author = vd.get("author") or micro.get("ownerChannelName")
        handle = None
        owner_url = micro.get("ownerProfileUrl", "") or ""
        m = _OWNER_URL_HANDLE_RE.search(owner_url)
        if m:
            handle = m.group(1)

        if not channel_id and not author:
            return

        if not _is_blocked(channel_id, author, handle, policy.youtube):
            return

        label = author or channel_id
        msg = policy.block_page.message or "This video is blocked by your network policy."
        reason = f"YouTube channel '{label}' blocked by policy"

        # Make the video unplayable: YouTube's player honours playabilityStatus.
        data["playabilityStatus"] = {
            "status": "ERROR",
            "reason": msg,
            "errorScreen": {
                "playerErrorMessageRenderer": {
                    "reason": {"simpleText": msg},
                    "subreason": {"simpleText": f"Blocked channel: {label}"},
                }
            },
        }
        # Drop stream URLs so playback cannot proceed even if status is ignored.
        data.pop("streamingData", None)

        flow.response.text = json.dumps(data)
        log_block(flow, reason, "youtube", policy)

    # --- Watch page HTML (direct load / reload) --------------------------------
    def _handle_watch_html(self, flow: http.HTTPFlow, policy) -> None:
        ct = flow.response.headers.get("content-type", "")
        if "text/html" not in ct:
            return
        try:
            html = flow.response.text
        except Exception:
            return

        cid_m = _CHANNEL_ID_RE.search(html)
        author_m = _AUTHOR_RE.search(html)
        handle_m = _HANDLE_RE.search(html)

        channel_id = cid_m.group(1) if cid_m else None
        author = _json_unescape(author_m.group(1)) if author_m else None
        handle = handle_m.group(1) if handle_m else None

        if not channel_id and not author:
            return

        if not _is_blocked(channel_id, author, handle, policy.youtube):
            return

        label = author or channel_id
        reason = f"YouTube channel '{label}' blocked by policy"
        flow.response = make_block_response(flow, reason, "youtube", policy)
