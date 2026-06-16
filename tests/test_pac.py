import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from management.api import pac


def test_pac_has_findproxy_and_proxy_directive():
    out = pac.render_pac("192.168.1.10", 8080)
    assert "function FindProxyForURL(url, host)" in out
    assert 'return "PROXY 192.168.1.10:8080";' in out


def test_pac_no_direct_fallback_fails_closed():
    # Traffic must stay filtered if the proxy is down: no "; DIRECT" fallback.
    out = pac.render_pac("10.0.0.1", 3128)
    assert "PROXY 10.0.0.1:3128" in out
    assert "; DIRECT" not in out


def test_pac_always_bypasses_local_and_private():
    out = pac.render_pac("p", 8080)
    assert "isPlainHostName(host)" in out
    assert 'host === "localhost"' in out
    assert 'isInNet(host, "192.168.0.0", "255.255.0.0")' in out


def test_pac_user_direct_hosts_include_subdomains():
    out = pac.render_pac("p", 8080, ["example.com"])
    assert 'shExpMatch(host, "example.com")' in out
    assert 'shExpMatch(host, "*.example.com")' in out


def test_pac_wildcard_entry_used_verbatim():
    out = pac.render_pac("p", 8080, ["*.ads.net"])
    assert 'shExpMatch(host, "*.ads.net")' in out
    # a wildcard entry should not get a redundant "*." prefix
    assert "*.*.ads.net" not in out


def test_pac_skips_blank_direct_entries():
    out = pac.render_pac("p", 8080, ["", "   "])
    assert "User-configured direct" not in out


def test_pac_ipv6_proxy_host_bracketed():
    out = pac.render_pac("[fd00::1]", 8080)
    assert 'return "PROXY [fd00::1]:8080";' in out
