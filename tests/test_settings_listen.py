import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.models import GlobalSettings, split_hostport, to_mitm_mode, parse_listen


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

    def test_socks5_passthrough(self):
        assert to_mitm_mode("socks5@0.0.0.0:1080") == "socks5@0.0.0.0:1080"

    def test_wireguard_passthrough(self):
        assert to_mitm_mode("wireguard@0.0.0.0:51820") == "wireguard@0.0.0.0:51820"

    def test_dns_passthrough(self):
        assert to_mitm_mode("dns@0.0.0.0:53") == "dns@0.0.0.0:53"

    def test_tun_passthrough(self):
        assert to_mitm_mode("tun") == "tun"

    def test_local_passthrough(self):
        assert to_mitm_mode("local") == "local"

    def test_bare_hostport_defaults_regular(self):
        assert to_mitm_mode("0.0.0.0:8080") == "regular@0.0.0.0:8080"


class TestParseListen:
    def test_socks5(self):
        assert parse_listen("socks5@1.2.3.4:1080") == ("socks5", "1.2.3.4", 1080)

    def test_bare_hostport(self):
        assert parse_listen("0.0.0.0:8080") == ("regular", "0.0.0.0", 8080)

    def test_tun(self):
        assert parse_listen("tun") == ("tun", "", 0)

    def test_wireguard(self):
        assert parse_listen("wireguard@0.0.0.0:51820") == ("wireguard", "0.0.0.0", 51820)

    def test_dns(self):
        assert parse_listen("dns@0.0.0.0:53") == ("dns", "0.0.0.0", 53)

    def test_local(self):
        assert parse_listen("local") == ("local", "", 0)


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

    def test_primary_port_skips_wireguard(self):
        s = GlobalSettings(proxy_listen=["wireguard@0.0.0.0:51820", "0.0.0.0:3128"])
        assert s.primary_proxy_port == 3128

    def test_primary_port_fallback_when_no_proxy_mode(self):
        s = GlobalSettings(proxy_listen=["dns@0.0.0.0:53"])
        assert s.primary_proxy_port == 8080


class TestBomTolerantSettings:
    def test_load_settings_with_bom(self, tmp_path, monkeypatch):
        # A settings.json saved with a UTF-8 BOM (e.g. PowerShell Set-Content
        # -Encoding utf8) must still load instead of silently reverting to
        # defaults.
        import management.api.routes.settings as settings_route
        cfg = tmp_path / "settings.json"
        cfg.write_text('{"mgmt_port": 9123}', encoding="utf-8-sig")
        monkeypatch.setattr(settings_route, "_SETTINGS_PATH", cfg)
        assert settings_route._load().mgmt_port == 9123


class TestLogPaths:
    def test_derived_from_logs_dir(self):
        s = GlobalSettings(logs_dir="/var/log/wf")
        assert s.blocks_log_path.replace("\\", "/") == "/var/log/wf/blocks.jsonl"
        assert s.request_log_path.replace("\\", "/") == "/var/log/wf/requests.jsonl"
