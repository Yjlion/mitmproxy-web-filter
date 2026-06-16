from __future__ import annotations
import fnmatch
from mitmproxy import http
from proxy.block_page import make_block_response
from shared.categories import store as category_store


def _host_matches(host: str, pattern: str) -> bool:
    """Match a hostname against a pattern (exact, *.domain, or glob)."""
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith("." + base)
    return fnmatch.fnmatch(host, pattern)


def _url_matches(host: str, url: str, pattern: str) -> bool:
    # Patterns with a path component are matched against the full URL;
    # everything else is treated as a host pattern (handles *.domain too).
    if "/" in pattern:
        return fnmatch.fnmatch(url, pattern) or url.startswith(pattern)
    return _host_matches(host, pattern)


class UrlFilter:
    def request(self, flow: http.HTTPFlow) -> None:
        policy = flow.metadata.get("policy")
        if not policy or not policy.url_filter.enabled:
            return

        cfg = policy.url_filter
        host = flow.request.pretty_host
        url = flow.request.pretty_url

        # Custom allow list overrides everything (including category blocks).
        for pattern in cfg.allow:
            if _url_matches(host, url, pattern):
                flow.metadata["url_allowed"] = True
                return

        for pattern in cfg.block:
            if _url_matches(host, url, pattern):
                flow.response = make_block_response(
                    flow, "URL blocked by policy", "url_filter", policy
                )
                return

        # Shared category blocklists.
        if cfg.categories:
            cat = category_store.match_any(host, cfg.categories)
            if cat:
                flow.response = make_block_response(
                    flow, f"Site category '{cat}' blocked by policy", "url_filter", policy
                )
                return
