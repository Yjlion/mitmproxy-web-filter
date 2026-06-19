"""
Shared SQLite log store for request and block events.

Architecture
------------
Two processes share a single DB file in `logs/` on local disk.
- **Writer** (proxy): one module-level persistent connection guarded by a
  threading.Lock. All mitmproxy hook calls run on one thread, so the lock is
  just a safety net.
- **Readers** (management API): open a fresh short-lived *read-only* connection
  per call. Thread-safe under uvicorn's threadpool.
WAL mode lets readers and the single writer coexist without blocking each other.
"""
from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Column definitions (export headers + INSERT order)
# ---------------------------------------------------------------------------
REQUEST_COLUMNS = (
    "ts", "method", "host", "path", "status",
    "action", "component", "policy", "client_ip", "user_agent",
)
BLOCK_COLUMNS = (
    "ts", "domain", "url", "reason",
    "component", "policy", "client_ip",
)

_TABLES = {
    "requests": REQUEST_COLUMNS,
    "blocks": BLOCK_COLUMNS,
}

# ---------------------------------------------------------------------------
# Module state
# ---------------------------------------------------------------------------
_db_path: str | None = None
_retention_days: int = 30
_log_requests: bool = True
_log_blocks: bool = True

_conn: sqlite3.Connection | None = None
_lock = threading.Lock()
_insert_count = 0
_PRUNE_EVERY = 500

_DDL = """
CREATE TABLE IF NOT EXISTS requests (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ts         INTEGER NOT NULL,
  method     TEXT,
  host       TEXT,
  path       TEXT,
  status     INTEGER,
  action     TEXT,
  component  TEXT,
  policy     TEXT,
  client_ip  TEXT,
  user_agent TEXT
);
CREATE INDEX IF NOT EXISTS idx_requests_ts ON requests(ts);

CREATE TABLE IF NOT EXISTS blocks (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  ts        INTEGER NOT NULL,
  domain    TEXT,
  url       TEXT,
  reason    TEXT,
  component TEXT,
  policy    TEXT,
  client_ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_blocks_ts ON blocks(ts);
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def configure(
    db_path: str,
    retention_days: int = 30,
    log_requests: bool = True,
    log_blocks: bool = True,
) -> None:
    """Initialise the module. Idempotent — safe to call from both processes."""
    global _db_path, _retention_days, _log_requests, _log_blocks, _conn
    _db_path = db_path
    _retention_days = retention_days
    _log_requests = log_requests
    _log_blocks = log_blocks

    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    with _lock:
        if _conn is not None:
            try:
                _conn.close()
            except Exception:
                pass
        _conn = _open_write_conn(db_path)
        _conn.executescript(_DDL)
        # Schema migration: add user_agent column if it is missing (introduced
        # after initial deployment so existing databases lack it).
        existing_cols = {
            row[1]
            for row in _conn.execute("PRAGMA table_info(requests)").fetchall()
        }
        if "user_agent" not in existing_cols:
            _conn.execute("ALTER TABLE requests ADD COLUMN user_agent TEXT")
        _conn.commit()

    prune()


def migrate_legacy(logs_dir: str | Path) -> None:
    """Import existing JSONL logs into the DB, then rename the files.

    Called once by the proxy on startup (after configure). Skipped if the table
    already has rows (so re-import on subsequent restarts is a no-op).
    """
    import json

    logs_dir = Path(logs_dir)

    _migrations = [
        ("requests.jsonl", "requests", REQUEST_COLUMNS),
        ("blocks.jsonl", "blocks", BLOCK_COLUMNS),
    ]

    for filename, table, columns in _migrations:
        src = logs_dir / filename
        if not src.exists():
            continue

        # Skip if the table already has data.
        with _lock:
            cur = _conn.execute(f"SELECT 1 FROM {table} LIMIT 1")  # noqa: S608
            already_imported = cur.fetchone() is not None

        if already_imported:
            continue

        rows: list[tuple] = []
        try:
            for line in src.read_text(encoding="utf-8-sig").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    rows.append(tuple(entry.get(c) for c in columns))
                except Exception:
                    pass
        except OSError:
            continue

        if rows:
            placeholders = ", ".join("?" * len(columns))
            col_list = ", ".join(columns)
            with _lock:
                _conn.executemany(
                    f"INSERT INTO {table} ({col_list}) VALUES ({placeholders})",  # noqa: S608
                    rows,
                )
                _conn.commit()

        # Rename to .imported (non-destructive).
        dest = logs_dir / (filename + ".imported")
        if dest.exists():
            dest = logs_dir / (filename + f".imported.{int(time.time())}")
        try:
            src.rename(dest)
        except OSError:
            pass


def log_request(entry: dict) -> None:
    """Insert a request row. No-op if log_requests is off or not configured."""
    global _insert_count
    if not _log_requests or _conn is None:
        return
    _insert(
        "requests",
        REQUEST_COLUMNS,
        tuple(entry.get(c) for c in REQUEST_COLUMNS),
    )
    _maybe_prune()


def log_block(entry: dict) -> None:
    """Insert a block row. No-op if log_blocks is off or not configured."""
    global _insert_count
    if not _log_blocks or _conn is None:
        return
    _insert(
        "blocks",
        BLOCK_COLUMNS,
        tuple(entry.get(c) for c in BLOCK_COLUMNS),
    )
    _maybe_prune()


def prune() -> None:
    """Delete rows older than the retention window."""
    if _retention_days <= 0 or _conn is None:
        return
    cutoff = int(time.time()) - _retention_days * 86400
    with _lock:
        _conn.execute("DELETE FROM requests WHERE ts < ?", (cutoff,))
        _conn.execute("DELETE FROM blocks WHERE ts < ?", (cutoff,))
        _conn.commit()


def tail(kind: str, limit: int) -> list[dict]:
    """Return up to *limit* most-recent rows from *kind* (newest first).

    *kind* must be ``'requests'`` or ``'blocks'``.
    """
    _validate_kind(kind)
    if _db_path is None:
        return []
    try:
        conn = _open_read_conn(_db_path)
    except Exception:
        return []
    try:
        cur = conn.execute(
            f"SELECT * FROM {kind} ORDER BY ts DESC, id DESC LIMIT ?",  # noqa: S608
            (limit,),
        )
        cols = [d[0] for d in cur.description]
        rows = cur.fetchall()
        # Drop the internal `id` column from output.
        return [_row_to_dict(cols, row) for row in rows]
    except Exception:
        return []
    finally:
        try:
            conn.close()
        except Exception:
            pass


def analytics(start_ts: float, window_hours: int = 24) -> dict:
    """Return the same aggregation dict that the old JSONL endpoint produced."""
    if _db_path is None:
        return _empty_analytics(window_hours)
    try:
        conn = _open_read_conn(_db_path)
    except Exception:
        return _empty_analytics(window_hours)
    try:
        ts = int(start_ts)

        # total_requests / total_blocks
        total_requests = conn.execute(
            "SELECT COUNT(*) FROM requests WHERE ts >= ?", (ts,)
        ).fetchone()[0]
        total_blocks = conn.execute(
            "SELECT COUNT(*) FROM blocks WHERE ts >= ?", (ts,)
        ).fetchone()[0]

        # request_actions
        request_actions = {
            row[0]: row[1]
            for row in conn.execute(
                "SELECT action, COUNT(*) FROM requests WHERE ts >= ? GROUP BY action", (ts,)
            ).fetchall()
        }

        # top_blocked_domains
        top_blocked_domains = [
            {"domain": row[0], "count": row[1]}
            for row in conn.execute(
                "SELECT domain, COUNT(*) c FROM blocks"
                " WHERE ts >= ? AND domain <> '' AND domain IS NOT NULL"
                " GROUP BY domain ORDER BY c DESC LIMIT 15",
                (ts,),
            ).fetchall()
        ]

        # blocks_by_component
        blocks_by_component = [
            {"component": (row[0] or "unknown"), "count": row[1]}
            for row in conn.execute(
                "SELECT component, COUNT(*) c FROM blocks WHERE ts >= ?"
                " GROUP BY component ORDER BY c DESC",
                (ts,),
            ).fetchall()
        ]

        # per_device
        per_device = [
            {
                "ip": (row[0] or "unknown"),
                "total": row[1],
                "blocked": row[2] or 0,
                "policy": row[3] or "",
            }
            for row in conn.execute(
                "SELECT client_ip, COUNT(*) total,"
                " SUM(action='blocked') blocked,"
                " MAX(policy) policy"
                " FROM requests WHERE ts >= ?"
                " GROUP BY client_ip ORDER BY total DESC",
                (ts,),
            ).fetchall()
        ]

        # blocks_timeline (hourly buckets)
        blocks_timeline = [
            {"ts": row[0], "count": row[1]}
            for row in conn.execute(
                "SELECT (ts/3600)*3600 bucket, COUNT(*) c"
                " FROM blocks WHERE ts >= ?"
                " GROUP BY bucket ORDER BY bucket",
                (ts,),
            ).fetchall()
        ]

        return {
            "window_hours": window_hours,
            "total_requests": total_requests,
            "total_blocks": total_blocks,
            "request_actions": request_actions,
            "top_blocked_domains": top_blocked_domains,
            "blocks_by_component": blocks_by_component,
            "per_device": per_device,
            "blocks_timeline": blocks_timeline,
        }
    except Exception:
        return _empty_analytics(window_hours)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def rows_in_range(kind: str, start_ts: int, end_ts: int) -> list[dict]:
    """Return all rows where start_ts <= ts <= end_ts, ordered by ts ASC.

    The internal ``id`` column is excluded from the result dicts.
    """
    _validate_kind(kind)
    if _db_path is None:
        return []
    try:
        conn = _open_read_conn(_db_path)
    except Exception:
        return []
    try:
        cur = conn.execute(
            f"SELECT * FROM {kind} WHERE ts >= ? AND ts <= ? ORDER BY ts ASC",  # noqa: S608
            (start_ts, end_ts),
        )
        cols = [d[0] for d in cur.description]
        rows = cur.fetchall()
        return [_row_to_dict(cols, row) for row in rows]
    except Exception:
        return []
    finally:
        try:
            conn.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _validate_kind(kind: str) -> None:
    if kind not in _TABLES:
        raise ValueError(f"kind must be one of {list(_TABLES)}, got {kind!r}")


def _open_write_conn(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    return conn


def _open_read_conn(db_path: str) -> sqlite3.Connection:
    uri = f"file:{db_path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
    conn.execute("PRAGMA busy_timeout=5000;")
    return conn


def _insert(table: str, columns: tuple, values: tuple) -> None:
    placeholders = ", ".join("?" * len(columns))
    col_list = ", ".join(columns)
    with _lock:
        _conn.execute(
            f"INSERT INTO {table} ({col_list}) VALUES ({placeholders})",  # noqa: S608
            values,
        )
        _conn.commit()


def _maybe_prune() -> None:
    global _insert_count
    _insert_count += 1
    if _insert_count >= _PRUNE_EVERY:
        _insert_count = 0
        prune()


def _row_to_dict(cols: list[str], row: tuple) -> dict:
    """Convert a row tuple to a dict, omitting the 'id' column."""
    return {c: v for c, v in zip(cols, row) if c != "id"}


def _empty_analytics(window_hours: int) -> dict:
    return {
        "window_hours": window_hours,
        "total_requests": 0,
        "total_blocks": 0,
        "request_actions": {},
        "top_blocked_domains": [],
        "blocks_by_component": [],
        "per_device": [],
        "blocks_timeline": [],
    }
