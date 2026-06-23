"""
proxy_auth.py — HTTP proxy authentication (407 challenge/response).

Registered second in proxy/main.py, immediately after ManagementAccess, so
management traffic is already pre-authorized before this addon runs.

Protocol:
  HTTPS tunnels:  auth is carried on the CONNECT request (http_connect hook).
                  On success the connection ID is remembered so that the inner
                  HTTP requests routed through that tunnel are not re-challenged.
  Plain HTTP:     auth is carried on every request (request hook).  After the
                  browser handles the first 407, it resends with credentials on
                  every subsequent request in the same TCP keep-alive connection.

Credentials are stored in config/settings.json as a PBKDF2-SHA256 hash, the
same scheme used for management UI auth.  The plaintext password never touches
disk; it does travel over the network in Base64 (HTTP Basic), so use this
feature on a trusted LAN or over HTTPS/VPN.

SOCKS5 proxy auth is a different sub-protocol (RFC 1929) that mitmproxy handles
at the TCP layer; this addon does not cover it.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import sys
from pathlib import Path

from mitmproxy import connection, http

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from shared.models import GlobalSettings

logger = logging.getLogger(__name__)

_project_root = Path(__file__).parent.parent.parent
_settings: GlobalSettings = GlobalSettings()

_REALM = "WebFilter Proxy"


def _load_settings() -> GlobalSettings:
    path = _project_root / "config" / "settings.json"
    if path.exists():
        return GlobalSettings.model_validate_json(path.read_text(encoding="utf-8-sig"))
    return GlobalSettings()


def verify_password(password: str, stored: str) -> bool:
    """PBKDF2-SHA256 check — identical scheme to management/api/auth.py."""
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(iters)
        )
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, AttributeError):
        return False


def _parse_basic(auth_header: str) -> tuple[str, str] | None:
    """Decode a Basic auth header → (username, password), or None if missing/malformed."""
    if not auth_header.lower().startswith("basic "):
        return None
    try:
        decoded = base64.b64decode(auth_header[6:]).decode("utf-8", errors="replace")
        username, _, password = decoded.partition(":")
        return username, password
    except Exception:
        return None


def _make_407() -> http.Response:
    return http.Response.make(
        407,
        b"Proxy Authentication Required",
        {
            "Proxy-Authenticate": f'Basic realm="{_REALM}"',
            "Content-Type": "text/plain",
            "Proxy-Connection": "close",
        },
    )


class ProxyAuth:
    def __init__(self) -> None:
        # Connection IDs that have been authenticated at the CONNECT stage.
        # Inner HTTP requests through those tunnels are implicitly authorized.
        self._authed_conns: set[str] = set()

    def load(self, loader) -> None:
        global _settings
        _settings = _load_settings()

    def running(self) -> None:
        global _settings
        _settings = _load_settings()

    def _enabled(self) -> bool:
        return _settings.proxy_auth_enabled and bool(_settings.proxy_auth_password_hash)

    def _valid(self, flow: http.HTTPFlow) -> bool:
        creds = _parse_basic(flow.request.headers.get("proxy-authorization", ""))
        if creds is None:
            return False
        username, password = creds
        return (
            username == _settings.proxy_auth_username
            and verify_password(password, _settings.proxy_auth_password_hash)
        )

    def http_connect(self, flow: http.HTTPFlow) -> None:
        """Called when a client opens an HTTPS tunnel (CONNECT).  Auth must be
        validated here; the inner requests won't carry Proxy-Authorization."""
        if flow.metadata.get("url_allowed"):
            # ManagementAccess already cleared this connection.
            self._authed_conns.add(flow.client_conn.id)
            return
        if not self._enabled():
            self._authed_conns.add(flow.client_conn.id)
            return
        if not self._valid(flow):
            flow.response = _make_407()
            return
        self._authed_conns.add(flow.client_conn.id)

    def request(self, flow: http.HTTPFlow) -> None:
        """Called for every plain-HTTP proxy request and for tunneled HTTPS
        requests after the CONNECT is established.  The latter have already
        been authenticated in http_connect, so we skip them."""
        if flow.metadata.get("url_allowed"):
            return
        if not self._enabled():
            return
        # Already cleared at CONNECT stage (covers all tunneled HTTPS requests).
        if flow.client_conn.id in self._authed_conns:
            return
        if not self._valid(flow):
            flow.response = _make_407()

    def clientdisconnect(self, client: connection.Client) -> None:
        self._authed_conns.discard(client.id)
