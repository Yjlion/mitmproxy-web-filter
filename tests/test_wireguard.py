import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

wg = pytest = None  # placeholders replaced below

import pytest
wg = pytest.importorskip("mitmproxy_rs.wireguard")

from management.api.routes.wireguard import build_wireguard_client_conf


class TestBuildWireguardClientConf:
    def test_conf_sections_present(self):
        sk = wg.genkey()
        ck = wg.genkey()
        conf = build_wireguard_client_conf(sk, ck, "example.com", 51820)
        assert "[Interface]" in conf
        assert "[Peer]" in conf

    def test_client_private_key(self):
        sk = wg.genkey()
        ck = wg.genkey()
        conf = build_wireguard_client_conf(sk, ck, "example.com", 51820)
        assert f"PrivateKey = {ck}" in conf

    def test_server_public_key(self):
        sk = wg.genkey()
        ck = wg.genkey()
        conf = build_wireguard_client_conf(sk, ck, "example.com", 51820)
        assert f"PublicKey = {wg.pubkey(sk)}" in conf

    def test_endpoint(self):
        sk = wg.genkey()
        ck = wg.genkey()
        conf = build_wireguard_client_conf(sk, ck, "example.com", 51820)
        assert "Endpoint = example.com:51820" in conf

    def test_allowed_ips(self):
        sk = wg.genkey()
        ck = wg.genkey()
        conf = build_wireguard_client_conf(sk, ck, "example.com", 51820)
        assert "AllowedIPs = 0.0.0.0/0" in conf
