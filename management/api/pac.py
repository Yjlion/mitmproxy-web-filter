"""Proxy auto-config (PAC) file generation.

Serves the same JavaScript as both /proxy.pac and /wpad.dat. Clients fetch this
and route traffic through the filtering proxy. Local/private destinations and
any explicitly configured hosts are sent DIRECT; everything else goes through
the proxy. The proxy is returned with no DIRECT fallback so traffic fails
closed (stays filtered) if the proxy is unreachable.
"""
from __future__ import annotations
import ipaddress
import json


def render_pac(
    proxy_host: str,
    proxy_port: int,
    direct_hosts: list[str] | None = None,
    direct_ips: list[str] | None = None,
) -> str:
    proxy = json.dumps(f"PROXY {proxy_host}:{proxy_port}")

    direct_clauses = []
    for raw in direct_hosts or []:
        h = (raw or "").strip()
        if not h:
            continue
        if "*" in h:
            direct_clauses.append(f"shExpMatch(host, {json.dumps(h)})")
        else:
            direct_clauses.append(
                f"shExpMatch(host, {json.dumps(h)}) || "
                f"shExpMatch(host, {json.dumps('*.' + h)})"
            )
    user_direct = ""
    if direct_clauses:
        joined = " ||\n      ".join(direct_clauses)
        user_direct = (
            "\n  // User-configured direct (non-proxied) hosts.\n"
            f"  if ({joined}) {{\n    return \"DIRECT\";\n  }}\n"
        )

    # Build isInNet / shExpMatch clauses for user-configured direct IPs/CIDRs.
    # IPv4 plain/CIDR → isInNet() inside the IPv4-literal guard block.
    # IPv6 → shExpMatch exact fallback (PAC isInNet is IPv4-only).
    ip_v4_clauses: list[str] = []
    ip_v6_clauses: list[str] = []
    for raw in direct_ips or []:
        entry = (raw or "").strip()
        if not entry:
            continue
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue  # skip unparseable entries silently
        if net.version == 4:
            network_addr = str(net.network_address)
            netmask = str(net.netmask)
            ip_v4_clauses.append(
                f"isInNet(host, {json.dumps(network_addr)}, {json.dumps(netmask)})"
            )
        else:
            # IPv6: PAC has no isInNet6; emit an exact shExpMatch fallback.
            # For a CIDR we only match the network address string exactly.
            if "/" in entry:
                exact = str(net.network_address)
            else:
                exact = entry
            ip_v6_clauses.append(f"shExpMatch(host, {json.dumps(exact)})")

    user_direct_ipv4 = ""
    if ip_v4_clauses:
        joined = " ||\n        ".join(ip_v4_clauses)
        user_direct_ipv4 = (
            "\n    // User-configured direct IPs / CIDRs.\n"
            f"    if ({joined}) {{\n      return \"DIRECT\";\n    }}\n"
        )

    user_direct_ipv6 = ""
    if ip_v6_clauses:
        joined = " ||\n      ".join(ip_v6_clauses)
        user_direct_ipv6 = (
            "\n  // User-configured direct IPv6 addresses.\n"
            f"  if ({joined}) {{\n    return \"DIRECT\";\n  }}\n"
        )

    return f"""function FindProxyForURL(url, host) {{
  host = host.toLowerCase();

  // Local / loopback / link-local and intranet (single-label) names go direct.
  if (isPlainHostName(host) ||
      host === "localhost" ||
      shExpMatch(host, "*.local")) {{
    return "DIRECT";
  }}

  // Private IP literals go direct (guarded so plain DNS names skip the lookups).
  if (/^\\d+\\.\\d+\\.\\d+\\.\\d+$/.test(host)) {{
    if (isInNet(host, "127.0.0.0", "255.0.0.0") ||
        isInNet(host, "10.0.0.0", "255.0.0.0") ||
        isInNet(host, "172.16.0.0", "255.240.0.0") ||
        isInNet(host, "192.168.0.0", "255.255.0.0") ||
        isInNet(host, "169.254.0.0", "255.255.0.0")) {{
      return "DIRECT";
    }}{user_direct_ipv4}
  }}
{user_direct_ipv6}{user_direct}
  return {proxy};
}}
"""
