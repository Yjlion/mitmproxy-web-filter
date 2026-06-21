"""
Cross-platform reader for the OS neighbor table (ARP cache for IPv4, NDP /
neighbor table for IPv6).

Used by two callers:
  * the proxy (``proxy/addons/policy_router.py``) to resolve a client IP to a
    MAC address so a policy can be matched by device MAC, and
  * the management API (``GET /api/tools/neighbors``) to offer a "scan local
    network" picker in the policy editor.

Hard limitation: the neighbor table only knows the MAC of hosts on the same
layer-2 segment as this machine. A device behind a router resolves to the
router's MAC. All reads are best-effort — any failure yields an empty result
and callers fall back to IP matching.

No user input ever reaches the command line: every subprocess uses a fixed,
hard-coded argument list.
"""
from __future__ import annotations

import re
import subprocess
import sys
import threading
import time

# Cache the parsed neighbor table for a short window so a busy proxy does not
# shell out on every request.
_TTL_SECONDS = 30.0
_lock = threading.Lock()
_cache: dict[str, str] = {}        # normalized ip -> normalized mac
_cache_ts: float = 0.0

_HEX12_RE = re.compile(r"^[0-9a-f]{12}$")


def normalize_mac(value: str) -> str:
    """Canonicalize a MAC to lowercase colon-separated form ``aa:bb:cc:dd:ee:ff``.

    Accepts ``:`` / ``-`` separators, Cisco dotted form (``aabb.ccdd.eeff``),
    and bare hex. Returns ``""`` for anything that is not exactly 12 hex digits.
    """
    if not value:
        return ""
    hexd = re.sub(r"[^0-9a-fA-F]", "", value).lower()
    if not _HEX12_RE.match(hexd):
        return ""
    return ":".join(hexd[i:i + 2] for i in range(0, 12, 2))


def _normalize_ip(ip: str) -> str:
    """Lowercase, strip a zone id, and unwrap IPv4-mapped IPv6 to plain IPv4."""
    ip = ip.split("%", 1)[0].strip().lower()
    if ip.startswith("::ffff:") and "." in ip:
        ip = ip[len("::ffff:"):]
    return ip


# ---------------------------------------------------------------------------
# Per-platform parsers (pure functions — fed captured text, never run a process)
# ---------------------------------------------------------------------------

_LINUX_NEIGH_RE = re.compile(
    r"^(?P<ip>\S+)\s+dev\s+(?P<iface>\S+)\s+.*?lladdr\s+(?P<mac>[0-9a-fA-F:]{17})",
)


def parse_linux_ip_neigh(text: str) -> list[dict]:
    """Parse ``ip neigh show`` output.

    Lines look like: ``192.168.1.50 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE``
    Entries without an ``lladdr`` (FAILED / INCOMPLETE) are skipped.
    """
    out: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or "lladdr" not in line:
            continue
        m = _LINUX_NEIGH_RE.match(line)
        if not m:
            continue
        mac = normalize_mac(m.group("mac"))
        if not mac:
            continue
        out.append({"ip": _normalize_ip(m.group("ip")), "mac": mac, "iface": m.group("iface")})
    return out


_PROC_ARP_RE = re.compile(
    r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+(?P<mac>[0-9a-fA-F:]{17})\s+\S*\s+(?P<iface>\S+)",
)


def parse_proc_net_arp(text: str) -> list[dict]:
    """Parse ``/proc/net/arp`` (IPv4 only) as a fallback when ``ip`` is absent.

    Columns: IP address / HW type / Flags / HW address / Mask / Device.
    The all-zero MAC marks an incomplete entry and is skipped.
    """
    out: list[dict] = []
    for line in text.splitlines()[1:]:  # skip header
        m = _PROC_ARP_RE.match(line.strip())
        if not m:
            continue
        mac = normalize_mac(m.group("mac"))
        if not mac or mac == "00:00:00:00:00:00":
            continue
        out.append({"ip": _normalize_ip(m.group("ip")), "mac": mac, "iface": m.group("iface")})
    return out


_WIN_ARP_RE = re.compile(
    r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?P<mac>[0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})\s",
)


def parse_windows_arp(text: str) -> list[dict]:
    """Parse Windows ``arp -a`` output (IPv4). MACs use ``-`` separators."""
    out: list[dict] = []
    for line in text.splitlines():
        m = _WIN_ARP_RE.match(line.strip())
        if not m:
            continue
        mac = normalize_mac(m.group("mac"))
        if not mac:
            continue
        out.append({"ip": _normalize_ip(m.group("ip")), "mac": mac, "iface": ""})
    return out


_WIN_NETSH_RE = re.compile(
    r"^(?P<ip>[0-9a-fA-F:]+:[0-9a-fA-F:]*|\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<mac>[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s",
)


def parse_windows_netsh(text: str) -> list[dict]:
    """Parse ``netsh interface ipv6 show neighbors`` output (IPv6 neighbors)."""
    out: list[dict] = []
    for line in text.splitlines():
        m = _WIN_NETSH_RE.match(line.strip())
        if not m:
            continue
        mac = normalize_mac(m.group("mac"))
        if not mac:
            continue
        out.append({"ip": _normalize_ip(m.group("ip")), "mac": mac, "iface": ""})
    return out


_BSD_ARP_RE = re.compile(
    r"\((?P<ip>[0-9a-fA-F:.]+)\)\s+at\s+(?P<mac>[0-9a-fA-F:]+)(?:\s+on\s+(?P<iface>\S+))?",
)


def parse_bsd_arp(text: str) -> list[dict]:
    """Parse macOS/BSD ``arp -an`` output (IPv4).

    ``? (192.168.1.50) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]``
    Incomplete entries show ``(incomplete)`` for the MAC and are skipped.
    """
    out: list[dict] = []
    for line in text.splitlines():
        m = _BSD_ARP_RE.search(line)
        if not m:
            continue
        mac = normalize_mac(m.group("mac"))
        if not mac:
            continue
        out.append({"ip": _normalize_ip(m.group("ip")), "mac": mac, "iface": m.group("iface") or ""})
    return out


_BSD_NDP_RE = re.compile(
    r"^(?P<ip>[0-9a-fA-F:][0-9a-fA-F:.%a-zA-Z0-9]*:[0-9a-fA-F:.%a-zA-Z0-9]*)\s+"
    r"(?P<mac>[0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})\s+(?P<iface>\S+)",
)


def parse_bsd_ndp(text: str) -> list[dict]:
    """Parse macOS/BSD ``ndp -an`` output (IPv6 neighbors).

    Columnar: ``fe80::1%en0  aa:bb:cc:dd:ee:02  en0  23s  R`` — the header row
    and ``(incomplete)`` entries don't match the MAC column and are skipped.
    """
    out: list[dict] = []
    for line in text.splitlines():
        m = _BSD_NDP_RE.match(line.strip())
        if not m:
            continue
        mac = normalize_mac(m.group("mac"))
        if not mac:
            continue
        out.append({"ip": _normalize_ip(m.group("ip")), "mac": mac, "iface": m.group("iface")})
    return out


# ---------------------------------------------------------------------------
# Process invocation (fixed argv; fail open)
# ---------------------------------------------------------------------------

def _run(argv: list[str]) -> str:
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=5, check=False,
        )
        return proc.stdout or ""
    except Exception:
        return ""


def _scan_linux() -> list[dict]:
    text = _run(["ip", "neigh", "show"])
    if text.strip():
        rows = parse_linux_ip_neigh(text)
        if rows:
            return rows
    # Fall back to the IPv4-only /proc table if `ip` is unavailable/empty.
    try:
        with open("/proc/net/arp", encoding="utf-8") as fh:
            return parse_proc_net_arp(fh.read())
    except OSError:
        return []


def _scan_windows() -> list[dict]:
    rows = parse_windows_arp(_run(["arp", "-a"]))
    rows += parse_windows_netsh(
        _run(["netsh", "interface", "ipv6", "show", "neighbors"])
    )
    return rows


def _scan_bsd() -> list[dict]:
    rows = parse_bsd_arp(_run(["arp", "-an"]))
    rows += parse_bsd_ndp(_run(["ndp", "-an"]))
    return rows


def _raw_scan() -> list[dict]:
    if sys.platform.startswith("linux"):
        return _scan_linux()
    if sys.platform.startswith("win"):
        return _scan_windows()
    if sys.platform == "darwin" or "bsd" in sys.platform:
        return _scan_bsd()
    return []


def _is_unicast(mac: str) -> bool:
    """True for an individually-addressed (unicast) MAC. Excludes broadcast
    (ff:ff:..) and multicast (LSB of the first octet set, e.g. 01:00:5e, 33:33)
    entries, which never identify a single device."""
    try:
        first = int(mac[:2], 16)
    except ValueError:
        return False
    return (first & 0x01) == 0


def scan() -> list[dict]:
    """Return the current neighbor table, de-duplicated by MAC and sorted by IP.

    Each entry is ``{"ip": str, "mac": str, "iface": str}``. Broadcast and
    multicast MACs are excluded since they never target a single device.
    Best-effort: returns ``[]`` on any platform/tooling failure.
    """
    seen: dict[str, dict] = {}
    for row in _raw_scan():
        mac = row["mac"]
        if mac and _is_unicast(mac) and mac not in seen:
            seen[mac] = row
    return sorted(seen.values(), key=lambda r: r["ip"])


def _refresh_cache() -> None:
    global _cache, _cache_ts
    rows = _raw_scan()
    _cache = {r["ip"]: r["mac"] for r in rows if r["ip"] and r["mac"]}
    _cache_ts = time.monotonic()


def lookup(ip: str) -> str | None:
    """Resolve a client IP to a normalized MAC, or ``None`` if unknown.

    The neighbor table is cached for ``_TTL_SECONDS`` so a busy proxy does not
    shell out on every request.
    """
    if not ip:
        return None
    key = _normalize_ip(ip)
    with _lock:
        if time.monotonic() - _cache_ts > _TTL_SECONDS or not _cache:
            _refresh_cache()
        return _cache.get(key)
