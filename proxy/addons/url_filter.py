from __future__ import annotations
from mitmproxy import http
from proxy.block_page import make_block_response
from proxy.matching import url_matches
from shared.categories import store as category_store


class UrlFilter:
    def request(self, flow: http.HTTPFlow) -> None:
        policy = flow.metadata.get("policy")
        if not policy or not policy.url_filter.enabled:
            return

        # Honor MITM passthrough (include-mode non-listed sites, User-Agent
        # rules): these flows skip all filtering, URL rules included. Without
        # this, matching clients would still be blocked here while every later
        # addon skips them.
        if flow.metadata.get("mitm_passthrough"):
            return

        cfg = policy.url_filter
        host = flow.request.pretty_host
        url = flow.request.pretty_url

        # Custom allow/block lists take precedence over categories.
        for pattern in cfg.allow:
            if url_matches(host, url, pattern):
                flow.metadata["url_allowed"] = True
                return

        for pattern in cfg.block:
            if url_matches(host, url, pattern):
                flow.response = make_block_response(
                    flow, "URL blocked by policy", "url_filter", policy
                )
                return

        # Shared categories, applied per mode.
        if cfg.categories:
            cat = category_store.match_any(host, cfg.categories)
            if cfg.mode == "whitelist":
                # Only listed categories are allowed; block everything else.
                if not cat:
                    flow.response = make_block_response(
                        flow, "Site not in an allowed category (whitelist)",
                        "url_filter", policy,
                    )
                return
            # blacklist: block domains that fall in a listed category
            if cat:
                flow.response = make_block_response(
                    flow, f"Site category '{cat}' blocked by policy", "url_filter", policy
                )
                return
