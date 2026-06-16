"""
MITM interception control.

Excluded sites are aggregated from all policies and applied globally via
mitmproxy's ignore_hosts option (managed by policy_router._sync_ignore_hosts).
This addon handles per-flow decisions for the "include-only" MITM mode.
"""
from __future__ import annotations
from mitmproxy import http
from proxy.block_page import make_block_response


def _host_in_list(host: str, sites: list[str]) -> bool:
    for s in sites:
        s = s.lstrip("*.")
        if host == s or host.endswith("." + s):
            return True
    return False


class MitmControl:
    def request(self, flow: http.HTTPFlow) -> None:
        """
        For "include" mode: if the policy only wants to MITM specific sites,
        requests to non-listed sites that somehow made it through (HTTP traffic)
        are passed without modification.
        """
        policy = flow.metadata.get("policy")
        if not policy:
            return

        cfg = policy.mitm
        if cfg.mode != "include" or not cfg.sites:
            return

        host = flow.request.pretty_host
        if not _host_in_list(host, cfg.sites):
            # Pass through — cannot do TLS bypass here (already connected),
            # but mark so response hooks skip filtering.
            flow.metadata["mitm_passthrough"] = True
