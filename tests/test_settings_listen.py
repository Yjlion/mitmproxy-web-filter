import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.models import GlobalSettings, split_hostport, to_mitm_mode


class TestSplitHostport:
    def test_ipv4(self):
        assert split_hostport("0.0.0.0:8080") == ("0.0.0.0", 8080)

    def test_ipv4_specific(self):
        assert split_hostport("192.168.1.10:3128") == ("192.168.1.10", 3128)

    def test_ipv6_bracketed(self):
        assert split_hostport("[::1]:8080") == ("::1", 8080)

    def test_ipv6_all_bracketed(self):
        assert split_hostport("[::]:8080") == ("::", 8080)

    def test_ipv6_bare(self):
        assert split_hostport("::1:8080") == ("::1", 8080)


class TestToMitmMode:
    def test_ipv4(self):
        assert to_mitm_mode("0.0.0.0:8080") == "regular@0.0.0.0:8080"

    def test_ipv6_bracketed_debrackets(self):
        # mitmproxy 12 wants IPv6 without brackets.
        assert to_mitm_mode("[::1]:8080") == "regular@::1:8080"

    def test_ipv6_all(self):
        assert to_mitm_mode("[::]:8080") == "regular@:::8080"


class TestProxyModesAndPort:
    def test_modes(self):
        s = GlobalSettings(proxy_listen=["0.0.0.0:8080", "[::]:8081"])
        assert s.proxy_modes == ["regular@0.0.0.0:8080", "regular@:::8081"]

    def test_primary_port(self):
        s = GlobalSettings(proxy_listen=["[::]:9090"])
        assert s.primary_proxy_port == 9090

    def test_blank_entries_dropped(self):
        s = GlobalSettings(proxy_listen=["", "  ", "0.0.0.0:8080"])
        assert s.proxy_listen == ["0.0.0.0:8080"]

    def test_empty_falls_back(self):
        s = GlobalSettings(proxy_listen=[])
        assert s.proxy_listen == ["0.0.0.0:8080"]


class TestLogPaths:
    def test_derived_from_logs_dir(self):
        s = GlobalSettings(logs_dir="/var/log/wf")
        assert s.blocks_log_path.replace("\\", "/") == "/var/log/wf/blocks.jsonl"
        assert s.request_log_path.replace("\\", "/") == "/var/log/wf/requests.jsonl"
