import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from shared import neighbors


class TestNormalizeMac:
    @pytest.mark.parametrize("raw", [
        "aa:bb:cc:dd:ee:ff",
        "AA:BB:CC:DD:EE:FF",
        "aa-bb-cc-dd-ee-ff",
        "AA-BB-CC-DD-EE-FF",
        "aabb.ccdd.eeff",
        "aabbccddeeff",
        "AABBCCDDEEFF",
    ])
    def test_accepts_and_canonicalizes(self, raw):
        assert neighbors.normalize_mac(raw) == "aa:bb:cc:dd:ee:ff"

    @pytest.mark.parametrize("bad", [
        "", "  ", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:ff:00",
        "zz:bb:cc:dd:ee:ff", "not-a-mac", "12345",
    ])
    def test_rejects_invalid(self, bad):
        assert neighbors.normalize_mac(bad) == ""


class TestLinuxParser:
    def test_ip_neigh(self):
        text = (
            "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n"
            "192.168.1.50 dev eth0 lladdr aa:bb:cc:dd:ee:ff STALE\n"
            "192.168.1.99 dev eth0  FAILED\n"
            "fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:02 router REACHABLE\n"
        )
        rows = neighbors.parse_linux_ip_neigh(text)
        macs = {r["ip"]: r["mac"] for r in rows}
        assert macs["192.168.1.50"] == "aa:bb:cc:dd:ee:ff"
        assert macs["192.168.1.1"] == "aa:bb:cc:dd:ee:01"
        assert macs["fe80::1"] == "aa:bb:cc:dd:ee:02"
        assert "192.168.1.99" not in macs  # FAILED, no lladdr
        assert rows[0]["iface"] == "eth0"

    def test_proc_net_arp(self):
        text = (
            "IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.168.1.50     0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n"
            "192.168.1.77     0x1         0x0         00:00:00:00:00:00     *        eth0\n"
        )
        rows = neighbors.parse_proc_net_arp(text)
        macs = {r["ip"]: r["mac"] for r in rows}
        assert macs == {"192.168.1.50": "aa:bb:cc:dd:ee:ff"}  # incomplete skipped
        assert rows[0]["iface"] == "eth0"


class TestWindowsParser:
    def test_arp_a(self):
        text = (
            "\nInterface: 192.168.1.10 --- 0x5\n"
            "  Internet Address      Physical Address      Type\n"
            "  192.168.1.1           aa-bb-cc-dd-ee-01     dynamic\n"
            "  192.168.1.50          aa-bb-cc-dd-ee-ff     dynamic\n"
            "  192.168.1.255         ff-ff-ff-ff-ff-ff     static\n"
        )
        rows = neighbors.parse_windows_arp(text)
        macs = {r["ip"]: r["mac"] for r in rows}
        assert macs["192.168.1.50"] == "aa:bb:cc:dd:ee:ff"
        assert macs["192.168.1.1"] == "aa:bb:cc:dd:ee:01"

    def test_netsh_ipv6(self):
        text = (
            "Interface 12: Wi-Fi\n\n"
            "Internet Address                              Physical Address   Type\n"
            "--------------------------------------------  -----------------  -----------\n"
            "fe80::1                                       aa-bb-cc-dd-ee-02  Reachable\n"
            "2001:db8::5                                   aa-bb-cc-dd-ee-ff  Stale\n"
        )
        rows = neighbors.parse_windows_netsh(text)
        macs = {r["ip"]: r["mac"] for r in rows}
        assert macs["2001:db8::5"] == "aa:bb:cc:dd:ee:ff"
        assert macs["fe80::1"] == "aa:bb:cc:dd:ee:02"


class TestBsdParser:
    def test_arp_an(self):
        text = (
            "? (192.168.1.1) at aa:bb:cc:dd:ee:01 on en0 ifscope [ethernet]\n"
            "? (192.168.1.50) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n"
            "? (192.168.1.77) at (incomplete) on en0 ifscope [ethernet]\n"
        )
        rows = neighbors.parse_bsd_arp(text)
        macs = {r["ip"]: r["mac"] for r in rows}
        assert macs["192.168.1.50"] == "aa:bb:cc:dd:ee:ff"
        assert "192.168.1.77" not in macs  # incomplete
        assert rows[0]["iface"] == "en0"

    def test_ndp_an(self):
        text = (
            "Neighbor                Linklayer Address  Netif Expire    St Flgs Prbs\n"
            "fe80::1%en0             aa:bb:cc:dd:ee:02  en0   23s       R\n"
        )
        rows = neighbors.parse_bsd_ndp(text)
        macs = {r["ip"]: r["mac"] for r in rows}
        assert macs["fe80::1"] == "aa:bb:cc:dd:ee:02"  # zone id stripped


class TestScanAndLookup:
    def test_scan_dedups_by_mac_and_sorts(self, monkeypatch):
        monkeypatch.setattr(neighbors, "_raw_scan", lambda: [
            {"ip": "192.168.1.50", "mac": "aa:bb:cc:dd:ee:ff", "iface": "eth0"},
            {"ip": "192.168.1.20", "mac": "12:22:33:44:55:66", "iface": "eth0"},
            {"ip": "192.168.1.51", "mac": "aa:bb:cc:dd:ee:ff", "iface": "eth0"},  # dup MAC
        ])
        rows = neighbors.scan()
        assert [r["ip"] for r in rows] == ["192.168.1.20", "192.168.1.50"]

    def test_scan_excludes_broadcast_and_multicast(self, monkeypatch):
        monkeypatch.setattr(neighbors, "_raw_scan", lambda: [
            {"ip": "192.168.1.50", "mac": "aa:bb:cc:dd:ee:ff", "iface": ""},
            {"ip": "192.168.1.255", "mac": "ff:ff:ff:ff:ff:ff", "iface": ""},   # broadcast
            {"ip": "224.0.0.22", "mac": "01:00:5e:00:00:16", "iface": ""},      # multicast
        ])
        rows = neighbors.scan()
        assert [r["mac"] for r in rows] == ["aa:bb:cc:dd:ee:ff"]

    def test_lookup_normalizes_mapped_ipv6(self, monkeypatch):
        monkeypatch.setattr(neighbors, "_raw_scan", lambda: [
            {"ip": "192.168.1.50", "mac": "aa:bb:cc:dd:ee:ff", "iface": "eth0"},
        ])
        neighbors._cache_ts = 0.0  # force refresh
        assert neighbors.lookup("::ffff:192.168.1.50") == "aa:bb:cc:dd:ee:ff"
        assert neighbors.lookup("192.168.1.99") is None

    def test_lookup_empty_ip(self):
        assert neighbors.lookup("") is None
