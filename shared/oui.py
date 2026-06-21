"""
OUI (Organizationally Unique Identifier) vendor lookup.

Provides a single helper ``vendor_for(mac)`` that maps a MAC address to its
IEEE-registered vendor name using a bundled data file.

The data file (``shared/data/oui.txt``) ships with the full Wireshark manuf
list (~39 k 24-bit MA-L entries). Re-run ``scripts/update_oui.sh``
(Linux/macOS) or ``scripts/update_oui.ps1`` (Windows) to refresh it.

File format: one entry per line, ``<6-hex-lowercase><TAB><Vendor Name>``.
Comment lines (starting with ``#``) and blank lines are skipped.

The table is loaded lazily and cached in memory; the file's mtime is checked
at most every 60 seconds, matching the policy of ``shared/categories.py``.
On any I/O or parse error the module fails open (returns ``""``).
"""
from __future__ import annotations

import threading
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_DATA_FILE = Path(__file__).parent / "data" / "oui.txt"
_MTIME_TTL = 60.0  # seconds between mtime checks

# ---------------------------------------------------------------------------
# Module-level state (thread-safe via a lock)
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_table: dict[str, str] = {}
_loaded_mtime: float = -1.0
_last_check: float = 0.0


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _load_file(path: Path) -> dict[str, str]:
    """Parse the OUI data file and return a prefix→vendor mapping."""
    table: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t", 1)
            if len(parts) != 2:
                continue
            prefix = parts[0].strip().lower()
            vendor = parts[1].strip()
            if len(prefix) == 6 and all(c in "0123456789abcdef" for c in prefix):
                table[prefix] = vendor
    except Exception:
        pass
    return table


def _maybe_reload() -> None:
    """Reload the table if the file has changed since the last load."""
    global _table, _loaded_mtime, _last_check

    now = time.monotonic()
    if now - _last_check < _MTIME_TTL:
        return
    _last_check = now

    try:
        mtime = _DATA_FILE.stat().st_mtime
    except OSError:
        # File missing — clear table and return.
        _table = {}
        _loaded_mtime = -1.0
        return

    if mtime != _loaded_mtime:
        _table = _load_file(_DATA_FILE)
        _loaded_mtime = mtime


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def vendor_for(mac: str) -> str:
    """Return the vendor name for a MAC address, or ``""`` if unknown.

    Accepts any MAC format supported by ``shared.neighbors.normalize_mac``
    (colon, hyphen, Cisco dot, or bare hex). Fails open on any error.
    """
    if not mac:
        return ""
    try:
        from shared.neighbors import normalize_mac
        normalized = normalize_mac(mac)
        if not normalized:
            return ""
        prefix = normalized.replace(":", "")[:6]

        with _lock:
            _maybe_reload()
            return _table.get(prefix, "")
    except Exception:
        return ""
