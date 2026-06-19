"""
MITM interception control.

Excluded sites are aggregated from all policies and applied globally via
mitmproxy's ignore_hosts option (managed by policy_router._sync_ignore_hosts).
This addon handles per-flow decisions for the "include-only" MITM mode.
"""
from __future__ import annotations
from mitmproxy import http
from proxy.block_page import make_block_response
from proxy.matching import domain_in_list


def _ua_matches(ua: str, tokens: list[str]) -> bool:
    """True if the User-Agent contains any token (case-insensitive substring)."""
    ua = ua.lower()
    return any(t.strip().lower() in ua for t in tokens if t.strip())


class MitmControl:
    def request(self, flow: http.HTTPFlow) -> None:
        """
        Mark flows that should bypass filtering.

        For "include" mode: if the policy only wants to MITM specific sites,
        requests to non-listed sites that somehow made it through (HTTP traffic)
        are passed without modification.

        For User-Agent rules: skip filtering for matching (exclude) or
        non-matching (include) clients. Like the site include mode, this only
        marks passthrough — it cannot un-intercept an already-decrypted
        connection (the User-Agent isn't visible until after TLS interception).
        """
        policy = flow.metadata.get("policy")
        if not policy:
            return

        cfg = policy.mitm

        # Site-based include mode: pass through non-listed sites.
        if cfg.mode == "include" and cfg.sites:
            host = flow.request.pretty_host
            if not domain_in_list(host, cfg.sites):
                flow.metadata["mitm_passthrough"] = True

        # User-Agent based passthrough.
        if cfg.ua_mode != "off" and cfg.user_agents:
            ua = flow.request.headers.get("user-agent", "")
            matched = _ua_matches(ua, cfg.user_agents)
            if (cfg.ua_mode == "exclude" and matched) or (
                cfg.ua_mode == "include" and not matched
            ):
                flow.metadata["mitm_passthrough"] = True
