"""
management_access.py — ensure the management server is always reachable
through the filtering proxy.

Registered FIRST in proxy/main.py, before PolicyRouter, so it runs before
any filtering addon can block management traffic.

Behavior:
  0. Pseudo-domain DNS resolution (``dns_request`` hook)
     When the proxy runs in ``dns`` mode (and therefore acts as the client's
     resolver — the usual case for transparent / WireGuard / dns-mode
     deployments), a query for ``mgmt_hostname`` is answered directly with the
     box's IPv4 address instead of being forwarded upstream (where it would
     NXDOMAIN).  Without this, ``http://web.filter`` never resolves on those
     deployments and the redirect below never gets a chance to fire — the only
     setups that worked were ones where the client used the box as an explicit
     HTTP proxy (which performs no DNS itself).

  1. Pseudo-domain redirect (``request`` hook)
     If the request host (case-insensitive) matches ``mgmt_hostname``
     (default ``web.filter``) the proxy returns a 302 redirect to
     ``http://<proxy_ip>:<mgmt_port>/``.  The same code path handles both
     plain HTTP and HTTPS-intercepted flows — by the time the request hook
     runs the TLS layer is already decrypted, so ``pretty_host`` is readable
     in both cases.

  2. Management passthrough (``request`` hook)
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
import logging
import socket
import sys
from pathlib import Path

from mitmproxy import dns, http

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from shared.models import GlobalSettings

logger = logging.getLogger(__name__)

_project_root: Path = Path(__file__).parent.parent.parent
_settings: GlobalSettings = GlobalSettings()
_detected_ipv4: str | None = None


def _load_settings() -> GlobalSettings:
    path = _project_root / "config" / "settings.json"
    if path.exists():
        return GlobalSettings.model_validate_json(path.read_text(encoding="utf-8-sig"))
    return GlobalSettings()


def _detect_primary_ipv4() -> str:
    """Best-effort: the box's primary outbound IPv4 (no packets are sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        try:
            s.close()
        except Exception:
            pass


def _mgmt_ipv4() -> str:
    """IPv4 to answer ``mgmt_hostname`` DNS queries with: the configured
    ``mgmt_hostname_ip`` if set, otherwise the auto-detected primary IPv4
    (detected once and cached)."""
    global _detected_ipv4
    configured = (_settings.mgmt_hostname_ip or "").strip()
    if configured:
        return configured
    if _detected_ipv4 is None:
        _detected_ipv4 = _detect_primary_ipv4()
    return _detected_ipv4


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

    def dns_request(self, flow: dns.DNSFlow) -> None:
        """Answer ``mgmt_hostname`` queries locally so the pseudo-domain
        resolves for clients that use the box as their DNS server. Any other
        name is left untouched and forwarded upstream as usual."""
        if flow.response is not None:
            return
        req = flow.request
        if req is None or not req.questions:
            return

        mgmt_hostname = (_settings.mgmt_hostname or "web.filter").lower()
        if not any(
            q.name.rstrip(".").lower() == mgmt_hostname for q in req.questions
        ):
            return  # not for us — let mitmproxy forward it upstream

        ip = _mgmt_ipv4()
        answers = []
        for q in req.questions:
            if q.name.rstrip(".").lower() != mgmt_hostname:
                continue
            # Answer A queries; reply NODATA for AAAA so clients fall back to v4.
            if q.type == dns.types.A:
                try:
                    answers.append(
                        dns.ResourceRecord.A(q.name, ipaddress.IPv4Address(ip))
                    )
                except ValueError:
                    pass
        flow.response = req.succeed(answers)

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
            # Gate the flow so no downstream addon re-processes it. mitmproxy
            # still runs every addon's request hook even after a response is
            # set, so without these flags doh_filter/url_filter would look up
            # the (non-resolvable) pseudo-domain and overwrite the 302 with a
            # block page.
            flow.metadata["url_allowed"] = True
            flow.metadata["mitm_passthrough"] = True
            return

        # --- 2. Management server passthrough ---
        if req.port == mgmt_port:
            proxy_ip_raw = (
                flow.client_conn.sockname[0] if flow.client_conn.sockname else ""
            )
            if _is_local_host(dest_host) or dest_host == proxy_ip_raw.lower():
                flow.metadata["url_allowed"] = True
                flow.metadata["mitm_passthrough"] = True
