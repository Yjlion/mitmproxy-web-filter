import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import proxy.addons.policy_router as pr
from proxy.addons.policy_router import get_policy
from shared.models import Policy, GlobalSettings


def _set(policies):
    pr._policies = policies


class TestIPv6Matching:
    def test_exact_ipv6(self):
        p = Policy(name="v6", source_ips=["2001:db8::1"])
        _set([p])
        assert get_policy("2001:db8::1") is p
        assert get_policy("2001:db8::2") is None

    def test_ipv6_cidr(self):
        p = Policy(name="v6net", source_ips=["2001:db8::/32"])
        _set([p])
        assert get_policy("2001:db8:abcd:1::5") is p
        assert get_policy("2001:dead::1") is None

    def test_ipv6_compressed_forms_equal(self):
        # Different textual forms of the same address must match.
        p = Policy(name="v6", source_ips=["2001:0db8:0000:0000:0000:0000:0000:0001"])
        _set([p])
        assert get_policy("2001:db8::1") is p

    def test_link_local_with_zone_id(self):
        p = Policy(name="ll", source_ips=["fe80::1"])
        _set([p])
        # Clients can arrive with a zone id like fe80::1%eth0
        assert get_policy("fe80::1%eth0") is p

    def test_mixed_v4_and_v6_sources(self):
        p = Policy(name="mixed", source_ips=["192.168.1.0/24", "2001:db8::/64"])
        _set([p])
        assert get_policy("192.168.1.50") is p
        assert get_policy("2001:db8::abc") is p
        assert get_policy("10.0.0.1") is None


class TestIPv4MappedDualStack:
    """When the proxy listens dual-stack, IPv4 clients appear as ::ffff:x.x.x.x.
    A policy written in plain IPv4 terms must still match them."""

    def test_mapped_matches_ipv4_cidr(self):
        p = Policy(name="lan", source_ips=["192.168.1.0/24"])
        _set([p])
        assert get_policy("::ffff:192.168.1.42") is p

    def test_mapped_matches_exact_ipv4(self):
        p = Policy(name="host", source_ips=["10.0.0.5"])
        _set([p])
        assert get_policy("::ffff:10.0.0.5") is p

    def test_mapped_no_false_match(self):
        p = Policy(name="lan", source_ips=["192.168.1.0/24"])
        _set([p])
        assert get_policy("::ffff:10.0.0.5") is None


class TestSettingsListen:
    def test_default(self):
        assert GlobalSettings().proxy_listen == ["0.0.0.0:8080"]

    def test_roundtrip(self):
        s = GlobalSettings(proxy_listen=["0.0.0.0:8080", "[::]:8080"], mgmt_host="::1")
        r = GlobalSettings.model_validate_json(s.model_dump_json())
        assert r.proxy_listen == ["0.0.0.0:8080", "[::]:8080"]
        assert r.mgmt_host == "::1"

    def test_legacy_migration(self):
        # Old flat schema must still load.
        s = GlobalSettings.model_validate({
            "proxy_port": 3128, "mgmt_port": 9000, "listen_host": "0.0.0.0",
            "blocks_log_path": "./logs/blocks.jsonl",
        })
        assert s.proxy_listen == ["0.0.0.0:3128"]
        assert s.mgmt_host == "0.0.0.0"
        assert s.mgmt_port == 9000
        assert s.logs_dir == "logs"
