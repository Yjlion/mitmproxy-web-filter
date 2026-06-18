from __future__ import annotations
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from mitmproxy import http
from proxy.block_page import make_block_response

# Engine definitions: (domains, safe_param, blocked_paths_images, blocked_paths_videos, blocked_paths_ai)
_ENGINES: list[dict] = [
    {
        "name": "google",
        "domains": {"www.google.com", "google.com"},
        "domain_suffix": ".google.",  # catches google.co.uk etc.
        "safe_param": ("safe", "active"),
        "path_prefix": "/search",
        "images_paths": ["/imghp"],
        "videos_paths": ["/videohp"],
        "ai_domains": {"gemini.google.com", "bard.google.com"},
        "images_param": ("tbm", "isch"),
        "videos_param": ("tbm", "vid"),
    },
    {
        "name": "bing",
        "domains": {"www.bing.com", "bing.com"},
        "domain_suffix": None,
        "safe_param": ("adlt", "strict"),
        "path_prefix": "/search",
        "images_paths": ["/images/"],
        "videos_paths": ["/videos/"],
        "ai_domains": {"copilot.microsoft.com"},
        "images_param": None,
        "videos_param": None,
    },
    {
        "name": "duckduckgo",
        "domains": {"duckduckgo.com", "www.duckduckgo.com"},
        "domain_suffix": None,
        "safe_param": ("kp", "1"),
        "path_prefix": "/",
        "images_paths": [],
        "videos_paths": [],
        "ai_domains": {"duckduckgo.com"},  # DuckDuckGo AI is same domain
        "images_param": ("iar", "images"),
        "videos_param": ("iar", "videos"),
    },
    {
        "name": "yahoo",
        "domains": {"search.yahoo.com"},
        "domain_suffix": ".yahoo.com",
        "safe_param": ("vm", "r"),
        "path_prefix": "/search",
        "images_paths": ["/images/search"],
        "videos_paths": ["/video/search"],
        "ai_domains": set(),
        "images_param": None,
        "videos_param": None,
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
        if engine["domain_suffix"] and engine["domain_suffix"] in host:
            return engine
        # AI assistants live on their own hostnames (e.g. copilot.microsoft.com
        # for bing) — match them so per-engine AI blocking can resolve.
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

        # Per-engine tab blocking. Absent entry = nothing blocked for this engine
        # (the SafeSearch parameter below is still enforced).
        eng_cfg = cfg.engines.get(engine["name"])
        block_images = bool(eng_cfg and eng_cfg.block_images_tab)
        block_videos = bool(eng_cfg and eng_cfg.block_videos_tab)
        block_ai = bool(eng_cfg and eng_cfg.block_ai_tab)

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

        # Enforce SafeSearch parameter on search queries
        safe_key, safe_val = engine["safe_param"]
        if path.startswith(engine["path_prefix"]):
            new_url = _inject_param(url, safe_key, safe_val)
            if new_url != url:
                flow.request.url = new_url
                flow.metadata["wf_action"] = "modified"
                flow.metadata["wf_component"] = "safesearch"
