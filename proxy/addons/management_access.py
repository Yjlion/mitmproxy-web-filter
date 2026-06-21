"""
management_access.py — ensure the management server is always reachable
through the filtering proxy.

Registered FIRST in proxy/main.py, before PolicyRouter, so it runs before
any filtering addon can block management traffic.

Behavior (request hook only):
  1. Pseudo-domain redirect
     If the request host (case-insensitive) matches ``mgmt_hostname``
     (default ``web.filter``) the proxy returns a 302 redirect to
     ``http://<proxy_ip>:<mgmt_port>/``.  The same code path handles both
     plain HTTP and HTTPS-intercepted flows — by the time the request hook
     runs the TLS layer is already decrypted, so ``pretty_host`` is readable
     in both cases.

  2. Management passthrough
     If the request is directed at the management server's port AND the
     destination host is a local/loopback address (or the same address the
     client used to reach the proxy) we mark the flow as allowed + passthrough
     so no filtering addon can block it:
       * ``flow.metadata["url_allowed"] = True``    — skips url_filter
       * ``flow.metadata["mitm_passthrough"] = True`` — skips remaining addons

Settings are loaded from ``config/settings.json`` (utf-8-sig) at ``load`` /
``running`` time, matching the pattern used by policy_router.py.  Because this
addon runs before PolicyRouter, settings are also loaded here so they are
available even before PolicyRouter initialises.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import sys
from pathlib import Path

from mitmproxy import http

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from shared.models import GlobalSettings

logger = logging.getLogger(__name__)

_project_root: Path = Path(__file__).parent.parent.parent
_settings: GlobalSettings = GlobalSettings()


def _load_settings() -> GlobalSettings:
    path = _project_root / "config" / "settings.json"
    if path.exists():
        return GlobalSettings.model_validate_json(path.read_text(encoding="utf-8-sig"))
    return GlobalSettings()


def _is_local_host(host: str) -> bool:
    """Return True if *host* is a loopback or unspecified (all-interfaces) address."""
    h = host.strip("[]").split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(h)
        return addr.is_loopback or addr.is_unspecified
    except ValueError:
        return False


class ManagementAccess:
    def load(self, loader):
        global _settings
        _settings = _load_settings()

    def running(self):
        global _settings
        _settings = _load_settings()

    def request(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        dest_host = req.pretty_host.lower()
        mgmt_hostname = (_settings.mgmt_hostname or "web.filter").lower()
        mgmt_port = _settings.mgmt_port

        # --- 1. Pseudo-domain redirect ---
        if dest_host == mgmt_hostname:
            # Determine the IP address the client used to reach the proxy.
            proxy_ip = flow.client_conn.sockname[0] if flow.client_conn.sockname else "127.0.0.1"
            # Bracket IPv6 addresses.
            if ":" in proxy_ip and not proxy_ip.startswith("["):
                proxy_ip = f"[{proxy_ip}]"
            location = f"http://{proxy_ip}:{mgmt_port}/"
            flow.response = http.Response.make(
                302, b"", {"Location": location, "Content-Type": "text/plain"}
            )
            return

        # --- 2. Management server passthrough ---
        if req.port == mgmt_port:
            proxy_ip_raw = (
                flow.client_conn.sockname[0] if flow.client_conn.sockname else ""
            )
            if _is_local_host(dest_host) or dest_host == proxy_ip_raw.lower():
                flow.metadata["url_allowed"] = True
                flow.metadata["mitm_passthrough"] = True
