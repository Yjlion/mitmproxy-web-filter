from __future__ import annotations
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from mitmproxy import http
from proxy.block_page import make_block_response

# Engine definitions.
# safe_param  — (key, value) injected into the request URL query string.
# safe_header — (name, value) injected as a request header (YouTube uses this).
# image_cdn_domains — CDN hostnames that serve image results for this engine;
#   blocked wholesale when block_images_tab is on (no path/param check needed).
_ENGINES: list[dict] = [
    {
        "name": "google",
        "domains": {"www.google.com", "google.com"},
        "domain_suffix": ".google.",  # catches google.co.uk etc.
        "safe_param": ("safe", "active"),
        "safe_header": None,
        "path_prefix": "/search",
        "images_paths": ["/imghp"],
        "videos_paths": ["/videohp"],
        "ai_domains": {"gemini.google.com", "bard.google.com"},
        "images_param": ("tbm", "isch"),
        "videos_param": ("tbm", "vid"),
        "image_cdn_domains": {"encrypted-tbn0.gstatic.com"},
    },
    {
        "name": "bing",
        "domains": {"www.bing.com", "bing.com"},
        "domain_suffix": None,
        "safe_param": ("adlt", "strict"),
        "safe_header": None,
        "path_prefix": "/search",
        "images_paths": ["/images/"],
        "videos_paths": ["/videos/"],
        "ai_domains": {"copilot.microsoft.com"},
        "images_param": None,
        "videos_param": None,
        # th.bing.com serves Bing image-search thumbnails
        "image_cdn_domains": {"th.bing.com"},
    },
    {
        "name": "duckduckgo",
        # ddg.gg is DDG's official short domain (redirects to duckduckgo.com)
        "domains": {"duckduckgo.com", "www.duckduckgo.com", "ddg.gg"},
        "domain_suffix": None,
        "safe_param": ("kp", "1"),
        "safe_header": None,
        "path_prefix": "/",
        "images_paths": [],
        "videos_paths": [],
        "ai_domains": {"duckduckgo.com"},  # DuckDuckGo AI is same domain
        "images_param": ("iar", "images"),
        "videos_param": ("iar", "videos"),
        "image_cdn_domains": set(),
    },
    {
        "name": "yahoo",
        "domains": {"search.yahoo.com"},
        "domain_suffix": ".yahoo.com",
        "safe_param": ("vm", "r"),
        "safe_header": None,
        "path_prefix": "/search",
        "images_paths": ["/images/search"],
        "videos_paths": ["/video/search"],
        "ai_domains": set(),
        "images_param": None,
        "videos_param": None,
        "image_cdn_domains": set(),
    },
    {
        "name": "youtube",
        # Restricted Mode is enforced via a request header, not a URL param.
        # Covers the main site, mobile, Music, and embedded players.
        "domains": {
            "www.youtube.com", "youtube.com", "m.youtube.com",
            "music.youtube.com", "youtu.be",
        },
        "domain_suffix": ".youtube.com",
        "safe_param": None,
        "safe_header": ("YouTube-Restrict", "Strict"),
        "path_prefix": "/",
        "images_paths": [],
        "videos_paths": [],
        "ai_domains": set(),
        "images_param": None,
        "videos_param": None,
        "image_cdn_domains": set(),
    },
]


def _inject_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[key] = [value]
    new_query = urlencode({k: v[0] for k, v in params.items()})
    return urlunparse(parsed._replace(query=new_query))


def _match_engine(host: str) -> dict | None:
    for engine in _ENGINES:
        if host in engine["domains"]:
            return engine
        if host in engine.get("image_cdn_domains", set()):
            return engine
        if engine["domain_suffix"] and engine["domain_suffix"] in host:
            return engine
        for ai_domain in engine.get("ai_domains", set()):
            if host == ai_domain or host.endswith("." + ai_domain):
                return engine
    return None


def _should_filter(host: str, cfg) -> bool:
    if cfg.include_only:
        return any(host == s or host.endswith("." + s) for s in cfg.include_only)
    if cfg.exclude:
        return not any(host == s or host.endswith("." + s) for s in cfg.exclude)
    return True


class SafeSearch:
    def request(self, flow: http.HTTPFlow) -> None:
        if flow.metadata.get("url_allowed") or flow.metadata.get("mitm_passthrough"):
            return

        policy = flow.metadata.get("policy")
        if not policy or not policy.safesearch.enabled:
            return

        host = flow.request.pretty_host
        if not _should_filter(host, policy.safesearch):
            return

        cfg = policy.safesearch
        engine = _match_engine(host)

        if not engine:
            return

        url = flow.request.pretty_url
        parsed = urlparse(url)
        path = parsed.path

        eng_cfg = cfg.engines.get(engine["name"])
        if eng_cfg and not eng_cfg.enabled:
            return
        block_images = bool(eng_cfg and eng_cfg.block_images_tab)
        block_videos = bool(eng_cfg and eng_cfg.block_videos_tab)
        block_ai = bool(eng_cfg and eng_cfg.block_ai_tab)

        # Image CDN domains: block wholesale when image tab blocking is active
        # for the parent engine (every path on these hosts serves image content).
        if host in engine.get("image_cdn_domains", set()):
            if block_images:
                flow.response = make_block_response(
                    flow, "Image search blocked by policy", "safesearch", policy
                )
            return

        # Block AI search engines/tabs
        if block_ai:
            for ai_domain in engine.get("ai_domains", set()):
                if host == ai_domain or host.endswith("." + ai_domain):
                    flow.response = make_block_response(
                        flow, "AI search blocked by policy", "safesearch", policy
                    )
                    return

        # Block image search tab
        if block_images:
            for img_path in engine.get("images_paths", []):
                if path.startswith(img_path):
                    flow.response = make_block_response(
                        flow, "Image search blocked by policy", "safesearch", policy
                    )
                    return
            img_param = engine.get("images_param")
            if img_param:
                params = parse_qs(parsed.query)
                if params.get(img_param[0]) == [img_param[1]]:
                    flow.response = make_block_response(
                        flow, "Image search blocked by policy", "safesearch", policy
                    )
                    return

        # Block video search tab
        if block_videos:
            for vid_path in engine.get("videos_paths", []):
                if path.startswith(vid_path):
                    flow.response = make_block_response(
                        flow, "Video search blocked by policy", "safesearch", policy
                    )
                    return
            vid_param = engine.get("videos_param")
            if vid_param:
                params = parse_qs(parsed.query)
                if params.get(vid_param[0]) == [vid_param[1]]:
                    flow.response = make_block_response(
                        flow, "Video search blocked by policy", "safesearch", policy
                    )
                    return

        # Header-based enforcement (YouTube Restricted Mode) — all paths
        safe_hdr = engine.get("safe_header")
        if safe_hdr:
            hdr_key, hdr_val = safe_hdr
            flow.request.headers[hdr_key] = hdr_val
            flow.metadata["wf_action"] = "modified"
            flow.metadata["wf_component"] = "safesearch"

        # URL param enforcement — paths under path_prefix
        safe_prm = engine.get("safe_param")
        if safe_prm and path.startswith(engine["path_prefix"]):
            safe_key, safe_val = safe_prm
            new_url = _inject_param(url, safe_key, safe_val)
            if new_url != url:
                flow.request.url = new_url
                flow.metadata["wf_action"] = "modified"
                flow.metadata["wf_component"] = "safesearch"
