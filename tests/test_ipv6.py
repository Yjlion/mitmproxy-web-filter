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


class TestMatchPrecedence:
    """Matching prefers specificity: exact IP > CIDR block > catch-all."""

    def test_exact_ip_beats_block(self):
        block = Policy(name="lan", source_ips=["192.168.1.0/24"])
        exact = Policy(name="kid", source_ips=["192.168.1.50"])
        # Block is listed first, but the exact match must still win.
        _set([block, exact])
        assert get_policy("192.168.1.50") is exact
        assert get_policy("192.168.1.51") is block

    def test_narrowest_block_wins(self):
        wide = Policy(name="wide", source_ips=["10.0.0.0/8"])
        narrow = Policy(name="narrow", source_ips=["10.1.2.0/24"])
        # Wide is listed first, but the narrower block must win.
        _set([wide, narrow])
        assert get_policy("10.1.2.5") is narrow
        assert get_policy("10.9.9.9") is wide

    def test_catch_all_is_last_resort(self):
        block = Policy(name="lan", source_ips=["192.168.1.0/24"])
        default = Policy(name="default", source_ips=[])
        _set([block, default])
        assert get_policy("192.168.1.5") is block
        assert get_policy("8.8.8.8") is default

    def test_exact_beats_block_across_addrs_dual_stack(self):
        block = Policy(name="lan", source_ips=["192.168.1.0/24"])
        exact = Policy(name="host", source_ips=["192.168.1.50"])
        _set([block, exact])
        # IPv4-mapped client should still prefer the exact match.
        assert get_policy("::ffff:192.168.1.50") is exact


class TestLoadPolicies:
    def test_bom_prefixed_file_loads(self, tmp_path):
        # A UTF-8 BOM (e.g. from PowerShell Set-Content -Encoding utf8) must not
        # silently drop the policy.
        (tmp_path / "kid.json").write_text(
            '{"name":"kid","source_ips":["10.0.0.5"]}', encoding="utf-8-sig"
        )
        loaded = pr.load_policies(tmp_path)
        assert [p.name for p in loaded] == ["kid"]


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
