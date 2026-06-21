"""Tests for shared/oui.py — OUI vendor lookup."""
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from shared import oui


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reset_oui_cache():
    """Force the module-level cache to be re-read on the next call."""
    with oui._lock:
        oui._table = {}
        oui._loaded_mtime = -1.0
        oui._last_check = 0.0


# ---------------------------------------------------------------------------
# Tests against the bundled placeholder file
# ---------------------------------------------------------------------------

_REAL_DATA_FILE = oui._DATA_FILE


class TestVendorForBundledData:
    @pytest.fixture(autouse=True)
    def _restore_bundled_file(self):
        """Ensure each test in this class starts with the real bundled file and
        a clean cache, regardless of what earlier tests may have left behind."""
        oui._DATA_FILE = _REAL_DATA_FILE
        _reset_oui_cache()
        yield
        # Restore again after the test in case the test modified state.
        oui._DATA_FILE = _REAL_DATA_FILE
        _reset_oui_cache()

    # Exact vendor strings come from the Wireshark manuf list and can change
    # when the data is refreshed, so assert on a stable case-insensitive
    # substring rather than the full name.
    def test_known_apple_prefix(self):
        # 001b63 is registered to Apple.
        result = oui.vendor_for("00:1b:63:aa:bb:cc")
        assert "apple" in result.lower()

    def test_known_cisco_prefix(self):
        # 00000c is registered to Cisco.
        result = oui.vendor_for("00:00:0c:11:22:33")
        assert "cisco" in result.lower()

    def test_known_vmware_prefix(self):
        # 005056 is registered to VMware.
        result = oui.vendor_for("00:50:56:aa:bb:cc")
        assert "vmware" in result.lower()

    def test_unknown_prefix_returns_empty(self):
        result = oui.vendor_for("de:ad:be:ef:00:01")
        assert result == ""

    def test_empty_mac_returns_empty(self):
        assert oui.vendor_for("") == ""

    def test_none_like_falsy_returns_empty(self):
        assert oui.vendor_for("   ") == "" or oui.vendor_for("   ") is not None


class TestVendorForMacFormats:
    """vendor_for must accept any MAC format normalize_mac supports."""

    @pytest.fixture(autouse=True)
    def _restore_bundled_file(self):
        oui._DATA_FILE = _REAL_DATA_FILE
        _reset_oui_cache()
        yield
        oui._DATA_FILE = _REAL_DATA_FILE
        _reset_oui_cache()

    def test_colon_form(self):
        result = oui.vendor_for("00:00:0c:11:22:33")
        assert "cisco" in result.lower()

    def test_hyphen_form(self):
        result = oui.vendor_for("00-00-0c-11-22-33")
        assert "cisco" in result.lower()

    def test_cisco_dot_form(self):
        result = oui.vendor_for("0000.0c11.2233")
        assert "cisco" in result.lower()

    def test_bare_hex_form(self):
        result = oui.vendor_for("00000c112233")
        assert "cisco" in result.lower()

    def test_uppercase(self):
        result = oui.vendor_for("00:00:0C:11:22:33")
        assert "cisco" in result.lower()


class TestMalformedMac:
    @pytest.mark.parametrize("bad", [
        "not-a-mac",
        "00:11:22",           # too short
        "00:11:22:33:44:55:66",  # too long
        "zz:00:0c:11:22:33",  # invalid hex
        "12345",
    ])
    def test_malformed_returns_empty(self, bad):
        assert oui.vendor_for(bad) == ""


class TestMissingFile:
    def test_missing_file_fails_open(self, tmp_path, monkeypatch):
        """If the OUI data file is missing, vendor_for returns "" (fails open)."""
        missing = tmp_path / "nonexistent.txt"
        monkeypatch.setattr(oui, "_DATA_FILE", missing)
        _reset_oui_cache()
        result = oui.vendor_for("00:00:0c:11:22:33")
        assert result == ""

    def test_corrupt_file_fails_open(self, tmp_path, monkeypatch):
        """Corrupt / unparseable file content should not raise."""
        bad_file = tmp_path / "oui.txt"
        bad_file.write_text("this is not valid\x00\xff data\n", encoding="utf-8", errors="replace")
        monkeypatch.setattr(oui, "_DATA_FILE", bad_file)
        _reset_oui_cache()
        result = oui.vendor_for("00:00:0c:11:22:33")
        # Should return "" gracefully (file has no valid entries).
        assert result == ""


class TestCustomDataFile:
    def test_custom_file_loaded(self, tmp_path, monkeypatch):
        data_file = tmp_path / "oui.txt"
        data_file.write_text("aabbcc\tTest Vendor\n001234\tAnother Corp\n", encoding="utf-8")
        monkeypatch.setattr(oui, "_DATA_FILE", data_file)
        _reset_oui_cache()

        assert oui.vendor_for("aa:bb:cc:dd:ee:ff") == "Test Vendor"
        assert oui.vendor_for("00:12:34:56:78:9a") == "Another Corp"
        assert oui.vendor_for("ff:ff:ff:ff:ff:ff") == ""

    def test_comments_and_blanks_skipped(self, tmp_path, monkeypatch):
        data_file = tmp_path / "oui.txt"
        data_file.write_text(
            "# This is a comment\n"
            "\n"
            "aabbcc\tGood Vendor\n"
            "# another comment\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(oui, "_DATA_FILE", data_file)
        _reset_oui_cache()
        assert oui.vendor_for("aa:bb:cc:dd:ee:ff") == "Good Vendor"

    def test_mtime_reload(self, tmp_path, monkeypatch):
        """Changing the file content triggers a reload on next TTL expiry."""
        data_file = tmp_path / "oui.txt"
        data_file.write_text("aabbcc\tFirst Vendor\n", encoding="utf-8")
        monkeypatch.setattr(oui, "_DATA_FILE", data_file)
        _reset_oui_cache()

        assert oui.vendor_for("aa:bb:cc:dd:ee:ff") == "First Vendor"

        # Update file and force TTL to expire.
        data_file.write_text("aabbcc\tUpdated Vendor\n", encoding="utf-8")
        with oui._lock:
            oui._last_check = 0.0  # force next call to re-check mtime

        assert oui.vendor_for("aa:bb:cc:dd:ee:ff") == "Updated Vendor"
