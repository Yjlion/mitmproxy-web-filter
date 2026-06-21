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


# --- Feature 1: direct IPs / CIDRs ---

def test_pac_ipv4_cidr_produces_isInNet():
    out = pac.render_pac("p", 8080, direct_ips=["203.0.113.0/24"])
    assert 'isInNet(host, "203.0.113.0", "255.255.255.0")' in out


def test_pac_plain_ipv4_produces_host_mask():
    out = pac.render_pac("p", 8080, direct_ips=["1.2.3.4"])
    assert 'isInNet(host, "1.2.3.4", "255.255.255.255")' in out


def test_pac_ipv4_cidr_inside_ipv4_literal_guard():
    """The isInNet clause for a direct IP must appear inside the IPv4 guard block
    (i.e. after the /^\d+\.\d+\.\d+\.\d+$/ test) so DNS names skip the call."""
    out = pac.render_pac("p", 8080, direct_ips=["10.20.0.0/16"])
    # Find the IPv4 guard and the isInNet for 10.20.0.0 — guard must come first.
    guard_pos = out.find(r"/^\d+\.\d+\.\d+\.\d+$/.test(host)")
    inet_pos = out.find('isInNet(host, "10.20.0.0", "255.255.0.0")')
    assert guard_pos != -1
    assert inet_pos != -1
    assert guard_pos < inet_pos


def test_pac_ipv6_address_falls_back_to_shExpMatch():
    out = pac.render_pac("p", 8080, direct_ips=["2001:db8::1"])
    assert 'shExpMatch(host, "2001:db8::1")' in out
    # Must NOT appear as isInNet (which is IPv4-only in PAC)
    assert 'isInNet(host, "2001:db8::1"' not in out


def test_pac_invalid_ip_entry_silently_skipped():
    # A non-IP entry should not crash and should not appear in the output.
    out = pac.render_pac("p", 8080, direct_ips=["not-an-ip", "256.0.0.1/24"])
    # No extra isInNet or shExpMatch beyond the built-in private-range ones.
    assert "not-an-ip" not in out
    assert "256.0.0.1" not in out


def test_pac_empty_direct_ips_leaves_output_unchanged():
    baseline = pac.render_pac("p", 8080)
    out = pac.render_pac("p", 8080, direct_ips=[])
    assert out == baseline


def test_pac_none_direct_ips_leaves_output_unchanged():
    baseline = pac.render_pac("p", 8080)
    out = pac.render_pac("p", 8080, direct_ips=None)
    assert out == baseline
