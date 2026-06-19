"""
DNS-over-HTTPS domain filtering.

Uses the standard RFC 8484 wireformat (application/dns-message), which every
DoH resolver supports — including NextDNS (https://dns.nextdns.io/<id>),
Cloudflare, CleanBrowsing and AdGuard. (The older Google/Cloudflare JSON API
is *not* universal: NextDNS, for one, doesn't serve it, which is why a
JSON-only client silently fails against it.)

A domain is considered blocked when the resolver returns NXDOMAIN or sinkholes
it to 0.0.0.0 / :: / 127.0.0.1 — the conventions filtering resolvers use.
"""
from __future__ import annotations
import asyncio
import time
import logging
from mitmproxy import http
from proxy.block_page import make_block_response
from proxy.matching import domain_in_list

logger = logging.getLogger("webfilter.doh")

try:
    import httpx
    import dns.message
    import dns.rdatatype
    import dns.rcode
    import dns.edns
    _DEPS_AVAILABLE = True
except ImportError:
    _DEPS_AVAILABLE = False

from ipaddress import ip_address

# Block signals, in order of how filtering resolvers indicate a blocked name:
#   1. NXDOMAIN (CleanBrowsing)
#   2. EDE — Extended DNS Errors, RFC 8914 (NextDNS, Cloudflare)
#   3. Sinkhole IPs (Cloudflare, NextDNS, AdGuard ad/tracker)
#   4. Provider block-page IPs (AdGuard family/adult content)
_BLOCK_ADDR_STRINGS = {
    "0.0.0.0", "::", "127.0.0.1",                 # sinkholes
    "94.140.14.35", "94.140.14.36",               # AdGuard block page (IPv4)
    "2a10:50c0::bad1:ff", "2a10:50c0::bad2:ff",   # AdGuard block page (IPv6)
}
_BLOCK_ADDRS = set()
for _s in _BLOCK_ADDR_STRINGS:
    try:
        _BLOCK_ADDRS.add(ip_address(_s))
    except ValueError:
        pass
# RFC 8914 EDE info-codes meaning "blocked": Blocked(15), Censored(16), Filtered(17).
_EDE_BLOCK_CODES = {15, 16, 17}

# (host, server) -> (blocked, expires_monotonic)
_cache: dict[tuple[str, str], tuple[bool, float]] = {}
_FAIL_TTL = 30      # cache a failed lookup briefly (fail-open, but retry soon)
_MAX_TTL = 600      # cap how long a verdict is cached

_client: "httpx.AsyncClient | None" = None


def _get_client() -> "httpx.AsyncClient":
    global _client
    if _client is None:
        # trust_env=False: never route DOH queries through a configured system
        # proxy (which could be *this* proxy) — they must go out directly.
        _client = httpx.AsyncClient(timeout=4.0, trust_env=False, http2=False)
    return _client


def _should_filter(host: str, cfg) -> bool:
    if cfg.include_only:
        return domain_in_list(host, cfg.include_only)
    if cfg.exclude:
        return not domain_in_list(host, cfg.exclude)
    return True


def _ede_block(msg) -> str | None:
    for opt in getattr(msg, "options", None) or []:
        if getattr(opt, "otype", None) == dns.edns.OptionType.EDE and \
                getattr(opt, "code", None) in _EDE_BLOCK_CODES:
            text = (getattr(opt, "text", "") or "").strip()
            return f"EDE {opt.code}" + (f": {text}" if text else "")
    return None


def _classify(messages: list) -> tuple[bool, str, int]:
    """Pure verdict logic over a set of DNS responses.
    Returns (blocked, detail, ttl)."""
    ttl = 300
    for msg in messages:
        if msg.rcode() == dns.rcode.NXDOMAIN:
            return True, "NXDOMAIN", 300
        ede = _ede_block(msg)
        if ede:
            return True, ede, 300
        for rrset in msg.answer:
            for rd in rrset:
                addr = getattr(rd, "address", None)
                if addr is not None:
                    try:
                        if ip_address(addr) in _BLOCK_ADDRS:
                            return True, f"block-ip {addr}", max(rrset.ttl, 1)
                    except ValueError:
                        pass
            if rrset.ttl:
                ttl = min(ttl, max(rrset.ttl, 1))
    return False, "", ttl


async def _resolve(host: str, server: str, rdtype) -> "dns.message.Message":
    # EDNS enabled so resolvers attach EDE (RFC 8914) block signals.
    query = dns.message.make_query(host, rdtype, use_edns=0, payload=1232)
    resp = await _get_client().post(
        server,
        content=query.to_wire(),
        headers={
            "content-type": "application/dns-message",
            "accept": "application/dns-message",
        },
    )
    resp.raise_for_status()
    return dns.message.from_wire(resp.content)


async def _query_doh(host: str, server: str) -> bool:
    server = server.strip()
    key = (host, server)
    now = time.monotonic()
    cached = _cache.get(key)
    if cached and now < cached[1]:
        return cached[0]

    results = await asyncio.gather(
        _resolve(host, server, dns.rdatatype.A),
        _resolve(host, server, dns.rdatatype.AAAA),
        return_exceptions=True,
    )
    messages = [m for m in results if not isinstance(m, Exception)]
    errors = [m for m in results if isinstance(m, Exception)]

    if not messages:
        # Every query failed — fail open, but log why and retry soon.
        e = errors[0]
        detail = f"{type(e).__name__}: {e}" if str(e) else type(e).__name__
        logger.warning(f"[doh_filter] lookup failed for {host} via {server}: {detail}")
        _cache[key] = (False, now + _FAIL_TTL)
        return False

    blocked, detail, ttl = _classify(messages)
    if blocked:
        logger.info(f"[doh_filter] {host} blocked by {server} ({detail})")
    _cache[key] = (blocked, now + min(ttl, _MAX_TTL))
    return blocked


class DohFilter:
    async def request(self, flow: http.HTTPFlow) -> None:
        if flow.metadata.get("url_allowed") or flow.metadata.get("mitm_passthrough"):
            return

        policy = flow.metadata.get("policy")
        if not policy or not policy.doh.enabled:
            return

        host = flow.request.pretty_host
        if not _should_filter(host, policy.doh):
            return

        if not _DEPS_AVAILABLE:
            logger.warning("[doh_filter] httpx/dnspython not installed; DOH filtering disabled")
            return

        if await _query_doh(host, policy.doh.server):
            flow.response = make_block_response(
                flow, f"Domain blocked by DNS policy ({policy.doh.server})", "doh", policy
            )
