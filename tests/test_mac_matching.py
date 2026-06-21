import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import proxy.addons.policy_router as pr
from proxy.addons.policy_router import get_policy
from shared.models import Policy


def _set(policies):
    pr._policies = policies


@pytest.fixture
def fixed_mac(monkeypatch):
    """Resolve every client IP to one fixed MAC, regardless of platform."""
    def _make(mac):
        monkeypatch.setattr(pr.neighbors, "lookup", lambda ip: mac)
    return _make


class TestMacMatching:
    def test_mac_match_basic(self, fixed_mac):
        fixed_mac("aa:bb:cc:dd:ee:ff")
        p = Policy(name="phone", source_macs=["aa:bb:cc:dd:ee:ff"])
        _set([p])
        assert get_policy("192.168.1.50") is p

    def test_mac_beats_exact_ip(self, fixed_mac):
        fixed_mac("aa:bb:cc:dd:ee:ff")
        by_mac = Policy(name="phone", source_macs=["aa:bb:cc:dd:ee:ff"])
        by_ip = Policy(name="lan", source_ips=["192.168.1.50"])
        # by_ip sorts first, but MAC is a higher tier and must win.
        _set([by_ip, by_mac])
        assert get_policy("192.168.1.50") is by_mac

    def test_mac_beats_cidr(self, fixed_mac):
        fixed_mac("aa:bb:cc:dd:ee:ff")
        by_mac = Policy(name="phone", source_macs=["aa:bb:cc:dd:ee:ff"])
        by_cidr = Policy(name="lan", source_ips=["192.168.1.0/24"])
        _set([by_cidr, by_mac])
        assert get_policy("192.168.1.50") is by_mac

    def test_no_mac_resolved_falls_back_to_ip(self, monkeypatch):
        monkeypatch.setattr(pr.neighbors, "lookup", lambda ip: None)
        by_mac = Policy(name="phone", source_macs=["aa:bb:cc:dd:ee:ff"])
        by_ip = Policy(name="lan", source_ips=["192.168.1.50"])
        _set([by_mac, by_ip])
        # Foreign-segment client (no MAC) → IP tiers apply.
        assert get_policy("192.168.1.50") is by_ip

    def test_mac_no_match_falls_back_to_ip(self, fixed_mac):
        fixed_mac("11:22:33:44:55:66")  # not in any policy
        by_mac = Policy(name="phone", source_macs=["aa:bb:cc:dd:ee:ff"])
        by_ip = Policy(name="lan", source_ips=["192.168.1.50"])
        _set([by_mac, by_ip])
        assert get_policy("192.168.1.50") is by_ip

    def test_match_is_case_and_separator_insensitive(self, fixed_mac):
        fixed_mac("aa:bb:cc:dd:ee:ff")
        # Stored with dashes + uppercase + Cisco dots → all normalize to colon form.
        p1 = Policy(name="dash", source_macs=["AA-BB-CC-DD-EE-FF"])
        _set([p1])
        assert get_policy("10.0.0.9") is p1

        p2 = Policy(name="cisco", source_macs=["aabb.ccdd.eeff"])
        _set([p2])
        assert get_policy("10.0.0.9") is p2

    def test_lookup_skipped_when_no_policy_has_macs(self, monkeypatch):
        # Optimization: lookup() must not be called when no policy uses MACs.
        called = {"n": 0}

        def _spy(ip):
            called["n"] += 1
            return "aa:bb:cc:dd:ee:ff"

        monkeypatch.setattr(pr.neighbors, "lookup", _spy)
        ip_only = Policy(name="lan", source_ips=["192.168.1.0/24"])
        _set([ip_only])
        assert get_policy("192.168.1.5") is ip_only
        assert called["n"] == 0
