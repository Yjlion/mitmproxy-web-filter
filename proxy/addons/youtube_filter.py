"""
YouTube filtering.

Channels can be listed three ways in the policy's `channels` list — all matched:
  * Channel ID:  UCxxxxxxxxxxxxxxxxxxxxxx
  * @handle:     @MrBeast   (or just MrBeast)
  * Display name: MrBeast   (case-insensitive)

youtube.com is a single-page app, so several interception points are needed.
A full document GET (`/watch`, `/@channel`, …) only happens on a direct load or
reload; in-app navigation instead hits the InnerTube JSON APIs. We cover both:

  * /youtubei/v1/get_watch — the combined watch call modern YouTube uses for
    in-app navigation. Its body is a JSON array carrying both the player response
    ([0].playerResponse) and the watch-next data ([1].watchNextResponse). This is
    the "video plays, only blocks on reload" path: blocking /player alone misses
    it because playback data now arrives here.
  * /youtubei/v1/player  — playback gate for some flows. We rewrite
    playabilityStatus to ERROR and drop streamingData so a blocked channel's
    video can't play.
  * /youtubei/v1/next    — watch metadata. Used to strip comments / the
    related-videos sidebar when configured.
  * /youtubei/v1/browse  — channel pages and the home feed (in-app nav). Used to
    block a channel page and, in whitelist mode, the home feed.
  * /watch HTML          — direct load / reload of a video.
  * channel-page HTML     — /@handle, /channel/UC…, /c/…, /user/… (direct/reload).
  * home HTML            — "/" and /feed/… (blocked in whitelist mode).
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
_GET_WATCH_PATH = "/youtubei/v1/get_watch"
_NEXT_PATH = "/youtubei/v1/next"
_BROWSE_PATH = "/youtubei/v1/browse"

# HTML / embedded-JSON extraction
_CHANNEL_ID_RE = re.compile(r'"channelId":"(UC[\w-]{22})"')
_AUTHOR_RE = re.compile(r'"author":"((?:[^"\\]|\\.)*)"')
_HANDLE_RE = re.compile(r'"canonicalBaseUrl":"/(@[\w.\-]+)"')
_OWNER_URL_HANDLE_RE = re.compile(r'/(@[\w.\-]+)')
# Channel-page specifics
_EXTERNAL_ID_RE = re.compile(r'"externalId":"(UC[\w-]{22})"')
_VANITY_RE = re.compile(r'"vanityChannelUrl":"https?://(?:www\.)?youtube\.com/(@[\w.\-]+)"')
_CHANNEL_TITLE_RE = re.compile(r'"channelMetadataRenderer":\{"title":"((?:[^"\\]|\\.)*)"')

# Channel-page URL forms
_CHANNEL_URL_RE = re.compile(r'^/(?:(channel)/(UC[\w-]{22})|(@[\w.\-]+)|(?:c|user)/[\w.\-]+)/?')


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
    """True if this channel appears in the configured list, matched by channel
    ID, display name, or @handle (case-insensitive for names/handles)."""
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


def _is_channel_path(path: str) -> bool:
    return bool(_CHANNEL_URL_RE.match(path))


def _is_home_path(path: str) -> bool:
    return path == "/" or path == "" or path.startswith("/feed")


# --- watch /next transforms -------------------------------------------------
def _watch_results(data: dict) -> list | None:
    try:
        return data["contents"]["twoColumnWatchNextResults"]["results"]["results"]["contents"]
    except (KeyError, TypeError):
        return None


def _strip_comments_from_next(data: dict) -> bool:
    """Remove the comments section from a watch /next response."""
    results = _watch_results(data)
    if not isinstance(results, list):
        return False
    keep = []
    changed = False
    for item in results:
        isr = item.get("itemSectionRenderer") if isinstance(item, dict) else None
        if isinstance(isr, dict) and isr.get("sectionIdentifier") in (
            "comment-item-section", "comments-entry-point",
        ):
            changed = True
            continue
        keep.append(item)
    if changed:
        data["contents"]["twoColumnWatchNextResults"]["results"]["results"]["contents"] = keep
    return changed


def _strip_sidebar_from_next(data: dict) -> bool:
    """Remove the related-videos sidebar (and autoplay) from a watch /next."""
    try:
        twocol = data["contents"]["twoColumnWatchNextResults"]
    except (KeyError, TypeError):
        return False
    if "secondaryResults" in twocol:
        del twocol["secondaryResults"]
        return True
    return False


def _browse_channel_identity(data: dict):
    """Pull (channel_id, title, handle) from a /browse response's metadata."""
    meta = (data.get("metadata") or {}).get("channelMetadataRenderer") or {}
    channel_id = meta.get("externalId")
    title = meta.get("title")
    handle = None
    vanity = meta.get("vanityChannelUrl") or ""
    m = _OWNER_URL_HANDLE_RE.search(vanity)
    if m:
        handle = m.group(1)
    return channel_id, title, handle


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

        path = flow.request.path.split("?", 1)[0]

        if path == _PLAYER_PATH:
            self._handle_player(flow, policy)
        elif path == _GET_WATCH_PATH:
            self._handle_get_watch(flow, policy)
        elif path == _NEXT_PATH:
            self._handle_next(flow, policy)
        elif path == _BROWSE_PATH:
            self._handle_browse(flow, policy)
        else:
            ct = flow.response.headers.get("content-type", "")
            if "text/html" not in ct:
                return
            if path.startswith("/watch"):
                self._handle_watch_html(flow, policy)
            elif _is_channel_path(path):
                self._handle_channel_html(flow, policy)
            elif _is_home_path(path):
                self._handle_home_html(flow, policy)

    # --- player-response blocking (shared by /player and /get_watch) -----------
    def _block_player_response(self, pr: dict, policy) -> str | None:
        """If this player response's channel is blocked, mutate it to be
        unplayable in place and return the channel label; else return None."""
        vd = pr.get("videoDetails", {}) or {}
        micro = (pr.get("microformat", {}) or {}).get("playerMicroformatRenderer", {}) or {}

        channel_id = vd.get("channelId") or micro.get("externalChannelId")
        author = vd.get("author") or micro.get("ownerChannelName")
        handle = None
        m = _OWNER_URL_HANDLE_RE.search(micro.get("ownerProfileUrl", "") or "")
        if m:
            handle = m.group(1)

        if not channel_id and not author:
            return None
        if not _is_blocked(channel_id, author, handle, policy.youtube):
            return None

        label = author or channel_id
        msg = policy.block_page.message or "This video is blocked by your network policy."
        # Make the video unplayable: YouTube's player honours playabilityStatus.
        pr["playabilityStatus"] = {
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
        pr.pop("streamingData", None)
        return label

    # --- InnerTube player API ---------------------------------------------------
    def _handle_player(self, flow: http.HTTPFlow, policy) -> None:
        ct = flow.response.headers.get("content-type", "")
        if "json" not in ct:
            return
        try:
            data = json.loads(flow.response.text)
        except Exception:
            return

        label = self._block_player_response(data, policy)
        if label:
            flow.response.text = json.dumps(data)
            log_block(flow, f"YouTube channel '{label}' blocked by policy", "youtube", policy)

    # --- InnerTube get_watch API (SPA video navigation) ------------------------
    def _handle_get_watch(self, flow: http.HTTPFlow, policy) -> None:
        yt = policy.youtube
        ct = flow.response.headers.get("content-type", "")
        if "json" not in ct:
            return
        try:
            data = json.loads(flow.response.text)
        except Exception:
            return

        # Body is an array of sub-responses; normalise to a list to iterate.
        elements = data if isinstance(data, list) else [data]
        changed = False
        label = None
        for el in elements:
            if not isinstance(el, dict):
                continue
            pr = el.get("playerResponse")
            if isinstance(pr, dict):
                lbl = self._block_player_response(pr, policy)
                if lbl:
                    changed = True
                    label = lbl
            wn = el.get("watchNextResponse")
            if isinstance(wn, dict):
                if yt.remove_comments:
                    changed |= _strip_comments_from_next(wn)
                if yt.remove_recommendations:
                    changed |= _strip_sidebar_from_next(wn)

        if changed:
            flow.response.text = json.dumps(data)
            if label:
                log_block(flow, f"YouTube channel '{label}' blocked by policy", "youtube", policy)

    # --- InnerTube next API (comments / sidebar) -------------------------------
    def _handle_next(self, flow: http.HTTPFlow, policy) -> None:
        yt = policy.youtube
        ct = flow.response.headers.get("content-type", "")
        if "json" not in ct:
            return
        try:
            data = json.loads(flow.response.text)
        except Exception:
            return

        changed = False
        if yt.remove_comments:
            changed |= _strip_comments_from_next(data)
        if yt.remove_recommendations:
            changed |= _strip_sidebar_from_next(data)

        if changed:
            flow.response.text = json.dumps(data)

    # --- InnerTube browse API (channel pages / home feed, SPA nav) -------------
    def _handle_browse(self, flow: http.HTTPFlow, policy) -> None:
        yt = policy.youtube
        ct = flow.response.headers.get("content-type", "")
        if "json" not in ct:
            return
        try:
            data = json.loads(flow.response.text)
        except Exception:
            return

        channel_id, title, handle = _browse_channel_identity(data)

        if channel_id or title or handle:
            if _is_blocked(channel_id, title, handle, yt):
                label = title or handle or channel_id
                self._blank_browse(flow, data, f"YouTube channel '{label}' blocked by policy", policy)
            return

        # No channel metadata → a feed (home / trending / subscriptions, etc.).
        if yt.mode == "whitelist" and yt.block_home:
            self._blank_browse(flow, data, "YouTube home/feed blocked (whitelist mode)", policy)

    def _blank_browse(self, flow, data, reason, policy) -> None:
        """Replace a /browse payload so no channel/feed content renders."""
        blanked = {"responseContext": data.get("responseContext", {})}
        flow.response.text = json.dumps(blanked)
        log_block(flow, reason, "youtube", policy)

    # --- Watch page HTML (direct load / reload) --------------------------------
    def _handle_watch_html(self, flow: http.HTTPFlow, policy) -> None:
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

    # --- Channel page HTML (direct load / reload) ------------------------------
    def _handle_channel_html(self, flow: http.HTTPFlow, policy) -> None:
        try:
            html = flow.response.text
        except Exception:
            return

        path = flow.request.path.split("?", 1)[0]

        # Identity from the URL first (most reliable), then from embedded JSON.
        channel_id = handle = name = None
        url_m = _CHANNEL_URL_RE.match(path)
        if url_m:
            if url_m.group(2):       # /channel/UC...
                channel_id = url_m.group(2)
            elif url_m.group(3):     # /@handle
                handle = url_m.group(3)

        ext_m = _EXTERNAL_ID_RE.search(html)
        if ext_m:
            channel_id = channel_id or ext_m.group(1)
        van_m = _VANITY_RE.search(html)
        if van_m:
            handle = handle or van_m.group(1)
        title_m = _CHANNEL_TITLE_RE.search(html)
        if title_m:
            name = _json_unescape(title_m.group(1))

        if not (channel_id or handle or name):
            return
        if not _is_blocked(channel_id, name, handle, policy.youtube):
            return

        label = name or handle or channel_id
        reason = f"YouTube channel '{label}' blocked by policy"
        flow.response = make_block_response(flow, reason, "youtube", policy)

    # --- Home / feed HTML (whitelist mode) -------------------------------------
    def _handle_home_html(self, flow: http.HTTPFlow, policy) -> None:
        yt = policy.youtube
        if yt.mode != "whitelist" or not yt.block_home:
            return
        reason = "YouTube home page blocked (whitelist mode)"
        flow.response = make_block_response(flow, reason, "youtube", policy)
