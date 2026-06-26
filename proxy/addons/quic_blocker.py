"""Strip Alt-Svc response headers to prevent QUIC (HTTP/3) bypass.

Browsers (especially Chrome) use the Alt-Svc header to discover that a server
supports HTTP/3 over QUIC (UDP/443). Once discovered, Chrome speaks QUIC
directly to that server, bypassing the TCP/TLS proxy entirely — defeating URL
filtering, SafeSearch enforcement, and YouTube channel blocking for Google and
YouTube domains.

Removing Alt-Svc forces the browser to stay on TCP/TLS where the proxy can
intercept it.  This is enabled per-policy via url_filter.block_quic = true.
"""
from __future__ import annotations

import logging

logger = logging.getLogger("webfilter.quic_blocker")

# Headers that advertise HTTP/3 / QUIC upgrade paths.
_QUIC_HEADERS = ("alt-svc",)


class QuicBlocker:
    def response(self, flow) -> None:
        if flow.metadata.get("url_allowed") or flow.metadata.get("mitm_passthrough"):
            return
        policy = flow.metadata.get("policy")
        if not (policy and policy.url_filter.block_quic):
            return
        if flow.response is None:
            return
        for hdr in _QUIC_HEADERS:
            if hdr in flow.response.headers:
                del flow.response.headers[hdr]
                logger.debug("[quic_blocker] stripped Alt-Svc from %s", flow.request.pretty_host)
