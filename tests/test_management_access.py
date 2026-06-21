"""Tests for proxy/addons/management_access.py."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import proxy.addons.management_access as ma
from proxy.addons.management_access import ManagementAccess
from shared.models import GlobalSettings


# ---------------------------------------------------------------------------
# Flow mock helpers (mirroring the pattern in test_url_filter.py)
# ---------------------------------------------------------------------------

def _make_flow(host: str, port: int, scheme: str = "http",
               client_sockname: tuple = ("192.168.1.100", 56789),
               proxy_sockname: tuple = ("192.168.1.1", 8080)):
    """Return a minimal flow mock with the fields management_access reads."""

    class Request:
        def __init__(self):
            self.pretty_host = host
            self.host = host
            self.port = port
            self.scheme = scheme

    class ClientConn:
        def __init__(self):
            self.peername = client_sockname
            self.sockname = proxy_sockname  # the address the client used to reach the proxy

    class Flow:
        def __init__(self):
            self.request = Request()
            self.client_conn = ClientConn()
            self.metadata = {}
            self.response = None

    return Flow()


def _addon_with_settings(**kwargs) -> ManagementAccess:
    """Return a ManagementAccess instance with patched module-level _settings."""
    s = GlobalSettings(**kwargs)
    ma._settings = s
    ma._detected_ipv4 = None  # reset auto-detect cache between tests
    return ManagementAccess()


def _make_dns_flow(name: str, qtype: int):
    """Return a minimal DNS flow with a single question, mirroring the fields
    management_access.dns_request reads."""
    from mitmproxy.dns import Question
    from mitmproxy.test import tflow

    flow = tflow.tdnsflow()
    flow.request.questions = [Question(name=name, type=qtype, class_=1)]
    flow.response = None
    return flow


# ---------------------------------------------------------------------------
# Pseudo-domain redirect tests
# ---------------------------------------------------------------------------

class TestPseudoDomainRedirect:
    def test_pseudo_domain_gets_302(self):
        addon = _addon_with_settings(mgmt_hostname="web.filter", mgmt_port=8000)
        flow = _make_flow("web.filter", 80, proxy_sockname=("10.0.0.1", 8080))
        addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 302
        loc = flow.response.headers["Location"]
        assert loc == "http://10.0.0.1:8000/"

    def test_redirect_gates_flow_against_downstream_addons(self):
        """The redirect must mark the flow allowed+passthrough. mitmproxy runs
        every addon's request hook even after a response is set, so without
        these gates doh_filter/url_filter would re-process the pseudo-domain
        and overwrite the 302 with a block page."""
        addon = _addon_with_settings(mgmt_hostname="web.filter", mgmt_port=8000)
        flow = _make_flow("web.filter", 80, proxy_sockname=("10.0.0.1", 8080))
        addon.request(flow)
        assert flow.response.status_code == 302
        assert flow.metadata.get("url_allowed") is True
        assert flow.metadata.get("mitm_passthrough") is True

    def test_pseudo_domain_case_insensitive(self):
        addon = _addon_with_settings(mgmt_hostname="web.filter", mgmt_port=8000)
        flow = _make_flow("WEB.FILTER", 80, proxy_sockname=("10.0.0.1", 8080))
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 302

    def test_redirect_target_uses_proxy_sockname_ip(self):
        """The Location header must point to the address the client used to reach
        the proxy (flow.client_conn.sockname[0]), not a hardcoded address."""
        addon = _addon_with_settings(mgmt_hostname="web.filter", mgmt_port=9000)
        flow = _make_flow("web.filter", 80, proxy_sockname=("172.16.5.10", 8080))
        addon.request(flow)
        assert "172.16.5.10:9000" in flow.response.headers["Location"]

    def test_redirect_ipv6_proxy_address_bracketed(self):
        """An IPv6 proxy address must be bracketed in the Location header."""
        addon = _addon_with_settings(mgmt_hostname="web.filter", mgmt_port=8000)
        flow = _make_flow("web.filter", 80, proxy_sockname=("fd00::1", 8080))
        addon.request(flow)
        loc = flow.response.headers["Location"]
        assert "[fd00::1]" in loc

    def test_https_intercepted_flow_also_redirected(self):
        """HTTPS flows are already decrypted by the time the request hook runs,
        so the same code path applies."""
        addon = _addon_with_settings(mgmt_hostname="web.filter", mgmt_port=8000)
        flow = _make_flow("web.filter", 443, scheme="https",
                          proxy_sockname=("10.0.0.1", 8080))
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 302

    def test_custom_pseudo_domain(self):
        addon = _addon_with_settings(mgmt_hostname="myproxy.local", mgmt_port=8000)
        flow = _make_flow("myproxy.local", 80, proxy_sockname=("10.0.0.1", 8080))
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 302


# ---------------------------------------------------------------------------
# DNS resolution of the pseudo-domain (dns_request hook)
# ---------------------------------------------------------------------------

class TestPseudoDomainDns:
    def test_a_query_answered_with_configured_ip(self):
        from mitmproxy import dns
        addon = _addon_with_settings(
            mgmt_hostname="web.filter", mgmt_hostname_ip="10.0.0.5"
        )
        flow = _make_dns_flow("web.filter", dns.types.A)
        addon.dns_request(flow)
        assert flow.response is not None
        ips = [str(r.ipv4_address) for r in flow.response.answers]
        assert ips == ["10.0.0.5"]

    def test_a_query_trailing_dot_and_case(self):
        from mitmproxy import dns
        for name in ("web.filter.", "WEB.FILTER"):
            addon = _addon_with_settings(
                mgmt_hostname="web.filter", mgmt_hostname_ip="10.0.0.5"
            )
            flow = _make_dns_flow(name, dns.types.A)
            addon.dns_request(flow)
            assert flow.response is not None
            assert [str(r.ipv4_address) for r in flow.response.answers] == ["10.0.0.5"]

    def test_aaaa_query_is_nodata(self):
        """AAAA for the pseudo-domain returns NOERROR with no answers so the
        client falls back to the A record rather than failing."""
        from mitmproxy import dns
        addon = _addon_with_settings(
            mgmt_hostname="web.filter", mgmt_hostname_ip="10.0.0.5"
        )
        flow = _make_dns_flow("web.filter", dns.types.AAAA)
        addon.dns_request(flow)
        assert flow.response is not None
        assert flow.response.answers == []

    def test_unrelated_name_forwarded(self):
        """A query for any other name is left untouched (forwarded upstream)."""
        from mitmproxy import dns
        addon = _addon_with_settings(
            mgmt_hostname="web.filter", mgmt_hostname_ip="10.0.0.5"
        )
        flow = _make_dns_flow("example.com", dns.types.A)
        addon.dns_request(flow)
        assert flow.response is None

    def test_custom_pseudo_domain_resolved(self):
        from mitmproxy import dns
        addon = _addon_with_settings(
            mgmt_hostname="myproxy.local", mgmt_hostname_ip="10.0.0.5"
        )
        flow = _make_dns_flow("myproxy.local", dns.types.A)
        addon.dns_request(flow)
        assert flow.response is not None
        assert [str(r.ipv4_address) for r in flow.response.answers] == ["10.0.0.5"]

    def test_blank_ip_autodetects(self, monkeypatch):
        """With no configured IP, the answer uses the auto-detected primary IPv4."""
        from mitmproxy import dns
        monkeypatch.setattr(ma, "_detect_primary_ipv4", lambda: "192.0.2.7")
        addon = _addon_with_settings(mgmt_hostname="web.filter", mgmt_hostname_ip="")
        flow = _make_dns_flow("web.filter", dns.types.A)
        addon.dns_request(flow)
        assert [str(r.ipv4_address) for r in flow.response.answers] == ["192.0.2.7"]


# ---------------------------------------------------------------------------
# Management server passthrough tests
# ---------------------------------------------------------------------------

class TestManagementPassthrough:
    def test_loopback_mgmt_port_sets_flags(self):
        addon = _addon_with_settings(mgmt_hostname="web.filter", mgmt_port=8000)
        flow = _make_flow("127.0.0.1", 8000, proxy_sockname=("127.0.0.1", 8080))
        addon.request(flow)

        assert flow.response is None  # no redirect
        assert flow.metadata.get("url_allowed") is True
        assert flow.metadata.get("mitm_passthrough") is True

    def test_localhost_hostname_mgmt_port_sets_flags(self):
        """::1 (IPv6 loopback) should also be treated as local."""
        addon = _addon_with_settings(mgmt_hostname="web.filter", mgmt_port=8000)
        flow = _make_flow("::1", 8000, proxy_sockname=("::1", 8080))
        addon.request(flow)
        assert flow.metadata.get("url_allowed") is True
        assert flow.metadata.get("mitm_passthrough") is True

    def test_proxy_own_ip_mgmt_port_sets_flags(self):
        """Requests to the proxy's own IP on the mgmt port are also allowed."""
        addon = _addon_with_settings(mgmt_hostname="web.filter", mgmt_port=8000)
        proxy_ip = "192.168.1.1"
        flow = _make_flow(proxy_ip, 8000, proxy_sockname=(proxy_ip, 8080))
        addon.request(flow)
        assert flow.metadata.get("url_allowed") is True
        assert flow.metadata.get("mitm_passthrough") is True

    def test_wrong_port_does_not_set_flags(self):
        """A local address on a different port must not be passthrough-marked."""
        addon = _addon_with_settings(mgmt_hostname="web.filter", mgmt_port=8000)
        flow = _make_flow("127.0.0.1", 80, proxy_sockname=("127.0.0.1", 8080))
        addon.request(flow)
        assert flow.response is None
        assert "url_allowed" not in flow.metadata
        assert "mitm_passthrough" not in flow.metadata

    def test_unspecified_address_mgmt_port_sets_flags(self):
        """0.0.0.0 is an unspecified address and is also treated as local."""
        addon = _addon_with_settings(mgmt_hostname="web.filter", mgmt_port=8000)
        flow = _make_flow("0.0.0.0", 8000, proxy_sockname=("0.0.0.0", 8080))
        addon.request(flow)
        assert flow.metadata.get("url_allowed") is True
        assert flow.metadata.get("mitm_passthrough") is True


# ---------------------------------------------------------------------------
# Unrelated traffic — must be untouched
# ---------------------------------------------------------------------------

class TestUnrelatedTrafficUntouched:
    def test_normal_http_request_untouched(self):
        addon = _addon_with_settings(mgmt_hostname="web.filter", mgmt_port=8000)
        flow = _make_flow("example.com", 80)
        addon.request(flow)
        assert flow.response is None
        assert "url_allowed" not in flow.metadata
        assert "mitm_passthrough" not in flow.metadata

    def test_normal_https_request_untouched(self):
        addon = _addon_with_settings(mgmt_hostname="web.filter", mgmt_port=8000)
        flow = _make_flow("google.com", 443, scheme="https")
        addon.request(flow)
        assert flow.response is None
        assert "url_allowed" not in flow.metadata

    def test_external_ip_on_mgmt_port_not_passthrough(self):
        """An external (non-local) host on the mgmt port is NOT passthrough."""
        addon = _addon_with_settings(mgmt_hostname="web.filter", mgmt_port=8000)
        # Destination host is a public IP, not the proxy's own address.
        flow = _make_flow("8.8.8.8", 8000, proxy_sockname=("192.168.1.1", 8080))
        addon.request(flow)
        assert flow.response is None
        assert "url_allowed" not in flow.metadata
        assert "mitm_passthrough" not in flow.metadata
