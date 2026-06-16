"""Proxy auto-config (PAC) file generation.

Serves the same JavaScript as both /proxy.pac and /wpad.dat. Clients fetch this
and route traffic through the filtering proxy. Local/private destinations and
any explicitly configured hosts are sent DIRECT; everything else goes through
the proxy. The proxy is returned with no DIRECT fallback so traffic fails
closed (stays filtered) if the proxy is unreachable.
"""
from __future__ import annotations
import json


def render_pac(proxy_host: str, proxy_port: int, direct_hosts: list[str] | None = None) -> str:
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
    }}
  }}
{user_direct}
  return {proxy};
}}
"""
