"""
Rolling log of every request the proxy handles (in addition to the blocks log).

Kept small: the file is trimmed to the last `max_entries` lines periodically so
it never grows unbounded. The management API reads the tail of this file.
"""
from __future__ import annotations
import json
from pathlib import Path

_path: Path | None = None
_max: int = 2000
_since_trim = 0
_TRIM_EVERY = 200  # trim after this many appends


def init(path: str, max_entries: int = 2000) -> None:
    global _path, _max, _since_trim
    _path = Path(path)
    _max = max(max_entries, 50)
    _since_trim = 0
    _path.parent.mkdir(parents=True, exist_ok=True)


def log_request(entry: dict) -> None:
    global _since_trim
    if not _path:
        return
    try:
        with _path.open("a") as f:
            f.write(json.dumps(entry) + "\n")
        _since_trim += 1
        if _since_trim >= _TRIM_EVERY:
            _since_trim = 0
            _trim()
    except OSError:
        pass


def _trim() -> None:
    try:
        lines = _path.read_text().splitlines()
        if len(lines) > _max:
            _path.write_text("\n".join(lines[-_max:]) + "\n")
    except OSError:
        pass
