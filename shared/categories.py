"""
Shared site categories.

Categories are domain blocklists shared across all policies. They are populated
on disk by scripts/update_categories.sh (from the IPFire squidguard list) under:

    categories/index.json          # [{name, count, updated}, ...] + metadata
    categories/<name>/domains       # one domain per line ('#' comments allowed)

A policy references categories by name in two independent places:
  * url_filter.categories — domains in these categories are blocked (block page)
  * mitm.categories       — domains in these categories bypass TLS interception

The policy's own custom lists (url_filter.allow/block, mitm.sites) take
precedence: an allow-list match short-circuits before any category block.

Matching is by registrable-ish suffix: a host matches a category if the host or
any of its parent domains (down to two labels) is present in the category set.
Domain sets are loaded lazily and cached, with the file mtime re-checked at most
once per CHECK_INTERVAL so an update via the script is picked up without a
restart but without a stat() on every request.
"""
from __future__ import annotations
import json
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
CATEGORIES_DIR = _ROOT / "categories"
INDEX_PATH = CATEGORIES_DIR / "index.json"
CHECK_INTERVAL = 60.0  # seconds between mtime re-checks of a loaded category


def configure(base) -> None:
    """Point the shared store + index at a different categories directory."""
    global INDEX_PATH
    store.base = Path(base)
    INDEX_PATH = store.base / "index.json"


def list_categories() -> list[dict]:
    """Category metadata from the on-disk index (empty if not populated yet)."""
    if not INDEX_PATH.exists():
        return []
    try:
        data = json.loads(INDEX_PATH.read_text())
    except Exception:
        return []
    return data.get("categories", []) if isinstance(data, dict) else []


def index_meta() -> dict:
    if not INDEX_PATH.exists():
        return {}
    try:
        data = json.loads(INDEX_PATH.read_text())
        return {k: v for k, v in data.items() if k != "categories"}
    except Exception:
        return {}


def _host_in_set(host: str, domains: frozenset[str]) -> bool:
    host = host.lower().rstrip(".")
    labels = host.split(".")
    # Check the full host then each parent domain, stopping before the bare TLD.
    for i in range(len(labels) - 1):
        if ".".join(labels[i:]) in domains:
            return True
    return False


class CategoryStore:
    def __init__(self, base: Path = CATEGORIES_DIR):
        self.base = base
        # name -> {"mtime": float, "set": frozenset, "checked": float}
        self._cache: dict[str, dict] = {}

    def domains(self, name: str) -> frozenset[str]:
        path = self.base / name / "domains"
        now = time.monotonic()
        entry = self._cache.get(name)
        if entry is not None and (now - entry["checked"]) < CHECK_INTERVAL:
            return entry["set"]
        try:
            mtime = path.stat().st_mtime
        except OSError:
            self._cache[name] = {"mtime": 0.0, "set": frozenset(), "checked": now}
            return frozenset()
        if entry is not None and entry["mtime"] == mtime:
            entry["checked"] = now
            return entry["set"]
        domains = self._load(path)
        self._cache[name] = {"mtime": mtime, "set": domains, "checked": now}
        return domains

    @staticmethod
    def _load(path: Path) -> frozenset[str]:
        out: set[str] = set()
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip().lower()
                    if line and not line.startswith("#"):
                        out.add(line)
        except OSError:
            return frozenset()
        return frozenset(out)

    def host_matches(self, host: str, name: str) -> bool:
        return _host_in_set(host, self.domains(name))

    def match_any(self, host: str, names: list[str]) -> str | None:
        """First category in `names` whose set contains `host` (or a parent)."""
        for name in names:
            if not name:
                continue
            if self.host_matches(host, name):
                return name
        return None


# Shared instance for the proxy addons.
store = CategoryStore()
