import base64
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from proxy.addons.proxy_auth import ProxyAuthGate, verify_password, _parse_basic, _make_407
from management.api import auth as mgmt_auth
from shared.models import GlobalSettings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_settings(**kw) -> GlobalSettings:
    return GlobalSettings.model_validate(kw)


def _basic_header(username: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()


class _Conn:
    def __init__(self, conn_id="conn-1"):
        self.id = conn_id
        self.peername = ("10.0.0.1", 1234)


class _Request:
    def __init__(self, headers=None):
        self.headers = headers or {}


class _Flow:
    def __init__(self, headers=None, conn_id="conn-1"):
        self.request = _Request(headers or {})
        self.client_conn = _Conn(conn_id)
        self.metadata = {}
        self.response = None


# ---------------------------------------------------------------------------
# verify_password (shared with management auth)
# ---------------------------------------------------------------------------

class TestVerifyPassword:
    def test_round_trip(self):
        h = mgmt_auth.hash_password("hunter2")
        assert verify_password("hunter2", h)
        assert not verify_password("wrong", h)

    def test_garbage_stored(self):
        assert not verify_password("x", "")
        assert not verify_password("x", "notahash")


# ---------------------------------------------------------------------------
# _parse_basic
# ---------------------------------------------------------------------------

class TestParseBasic:
    def test_valid(self):
        assert _parse_basic(_basic_header("alice", "s3cret")) == ("alice", "s3cret")

    def test_password_with_colon(self):
        # Password may contain colons — only the first colon separates user:pass
        assert _parse_basic(_basic_header("alice", "a:b:c")) == ("alice", "a:b:c")

    def test_missing(self):
        assert _parse_basic("") is None
        assert _parse_basic("Bearer token123") is None

    def test_malformed_base64(self):
        assert _parse_basic("Basic !!!notbase64!!!") is None


# ---------------------------------------------------------------------------
# ProxyAuth addon — auth disabled
# ---------------------------------------------------------------------------

class TestProxyAuthDisabled:
    def setup_method(self):
        import proxy.addons.proxy_auth as mod
        mod._settings = _make_settings(proxy_auth_enabled=False)
        self.addon = ProxyAuthGate()

    def test_connect_passes_through(self):
        flow = _Flow()
        self.addon.http_connect(flow)
        assert flow.response is None
        assert "conn-1" in self.addon._authed_conns

    def test_request_passes_through(self):
        flow = _Flow()
        self.addon.request(flow)
        assert flow.response is None


# ---------------------------------------------------------------------------
# ProxyAuth addon — auth enabled
# ---------------------------------------------------------------------------

class TestProxyAuthEnabled:
    def setup_method(self):
        import proxy.addons.proxy_auth as mod
        ph = mgmt_auth.hash_password("letmein")
        mod._settings = _make_settings(
            proxy_auth_enabled=True,
            proxy_auth_username="alice",
            proxy_auth_password_hash=ph,
        )
        self.addon = ProxyAuthGate()

    def test_connect_no_credentials_returns_407(self):
        flow = _Flow()
        self.addon.http_connect(flow)
        assert flow.response is not None
        assert flow.response.status_code == 407
        assert "Proxy-Authenticate" in flow.response.headers
        assert "conn-1" not in self.addon._authed_conns

    def test_connect_wrong_password_returns_407(self):
        flow = _Flow({"proxy-authorization": _basic_header("alice", "wrong")})
        self.addon.http_connect(flow)
        assert flow.response is not None
        assert flow.response.status_code == 407

    def test_connect_wrong_username_returns_407(self):
        flow = _Flow({"proxy-authorization": _basic_header("bob", "letmein")})
        self.addon.http_connect(flow)
        assert flow.response is not None
        assert flow.response.status_code == 407

    def test_connect_valid_credentials_passes(self):
        flow = _Flow({"proxy-authorization": _basic_header("alice", "letmein")})
        self.addon.http_connect(flow)
        assert flow.response is None
        assert "conn-1" in self.addon._authed_conns

    def test_tunneled_request_skips_reauth(self):
        """Inner HTTPS request on an authenticated CONNECT connection is not re-challenged."""
        # Authenticate the connection first
        flow_connect = _Flow(
            {"proxy-authorization": _basic_header("alice", "letmein")}, conn_id="conn-tls"
        )
        self.addon.http_connect(flow_connect)
        assert "conn-tls" in self.addon._authed_conns

        # Inner request has no Proxy-Authorization header
        flow_inner = _Flow({}, conn_id="conn-tls")
        self.addon.request(flow_inner)
        assert flow_inner.response is None

    def test_plain_http_no_credentials_returns_407(self):
        flow = _Flow()
        self.addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 407

    def test_plain_http_valid_credentials_passes(self):
        flow = _Flow({"proxy-authorization": _basic_header("alice", "letmein")})
        self.addon.request(flow)
        assert flow.response is None

    def test_plain_http_wrong_credentials_returns_407(self):
        flow = _Flow({"proxy-authorization": _basic_header("alice", "nope")})
        self.addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 407

    def test_url_allowed_skips_auth(self):
        """Management traffic (url_allowed=True) bypasses proxy auth."""
        flow_connect = _Flow()
        flow_connect.metadata["url_allowed"] = True
        self.addon.http_connect(flow_connect)
        assert flow_connect.response is None

        flow_req = _Flow()
        flow_req.metadata["url_allowed"] = True
        self.addon.request(flow_req)
        assert flow_req.response is None

    def test_clientdisconnect_removes_conn(self):
        # Authenticate and then disconnect
        flow = _Flow({"proxy-authorization": _basic_header("alice", "letmein")})
        self.addon.http_connect(flow)
        assert "conn-1" in self.addon._authed_conns

        class _Client:
            id = "conn-1"
        self.addon.client_disconnected(_Client())
        assert "conn-1" not in self.addon._authed_conns


# ---------------------------------------------------------------------------
# Settings model — proxy auth fields
# ---------------------------------------------------------------------------

class TestGlobalSettingsProxyAuth:
    def test_defaults(self):
        s = GlobalSettings()
        assert s.proxy_auth_enabled is False
        assert s.proxy_auth_username == ""
        assert s.proxy_auth_password_hash == ""

    def test_roundtrip(self):
        ph = mgmt_auth.hash_password("test")
        s = GlobalSettings(proxy_auth_enabled=True, proxy_auth_username="u", proxy_auth_password_hash=ph)
        j = s.model_dump_json()
        s2 = GlobalSettings.model_validate_json(j)
        assert s2.proxy_auth_enabled is True
        assert s2.proxy_auth_username == "u"
        assert s2.proxy_auth_password_hash == ph

    def test_legacy_settings_without_proxy_auth(self):
        """Old settings.json without proxy_auth fields loads with safe defaults."""
        old_json = '{"proxy_listen": ["0.0.0.0:8080"], "mgmt_port": 8000}'
        s = GlobalSettings.model_validate_json(old_json)
        assert s.proxy_auth_enabled is False
        assert s.proxy_auth_password_hash == ""
