#!/usr/bin/env python3
"""Diagnostic: query a DoH server (RFC 8484 wireformat) for a domain and print
the full response, so you can see exactly how the resolver signals a block.

Usage:
  .venv/bin/python scripts/doh_check.py <domain> [doh-server-url]

Defaults to the DOH server of the first policy that has one, else NextDNS.
"""
from __future__ import annotations
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx
import dns.message
import dns.rdatatype
import dns.rcode


def _default_server() -> str:
    for f in sorted((Path(__file__).parent.parent / "policies").glob("*.json")):
        try:
            import json
            d = json.loads(f.read_text())
            s = d.get("doh", {}).get("server", "").strip()
            if s:
                return s
        except Exception:
            pass
    return "https://dns.nextdns.io/4f5215"


async def query(host: str, server: str, rdtype) -> None:
    q = dns.message.make_query(host, rdtype)
    async with httpx.AsyncClient(timeout=6.0, trust_env=False) as c:
        r = await c.post(
            server,
            content=q.to_wire(),
            headers={"content-type": "application/dns-message",
                     "accept": "application/dns-message"},
        )
    tname = dns.rdatatype.to_text(rdtype)
    print(f"\n=== {tname}  (HTTP {r.status_code}, {len(r.content)} bytes) ===")
    if r.status_code != 200:
        print("  body:", r.content[:200])
        return
    msg = dns.message.from_wire(r.content)
    print("  rcode :", dns.rcode.to_text(msg.rcode()))
    if not msg.answer:
        print("  answer: (none)")
    for rrset in msg.answer:
        for rd in rrset:
            print(f"  answer: {rrset.name} {rrset.ttl} {dns.rdatatype.to_text(rrset.rdtype)} "
                  f"{getattr(rd, 'address', rd.to_text())}")


async def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    host = sys.argv[1]
    server = sys.argv[2] if len(sys.argv) > 2 else _default_server()
    print(f"Querying {server} for {host!r}")
    await query(host, server, dns.rdatatype.A)
    await query(host, server, dns.rdatatype.AAAA)


if __name__ == "__main__":
    asyncio.run(main())
