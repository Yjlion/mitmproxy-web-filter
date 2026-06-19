# Implementation Plan — SQLite Logging + CSV/XLSX Export

**Status:** approved for execution. Hand to Sonnet.
**Scope:** Replace the JSONL log files with a SQLite store (30-day configurable
retention) and add CSV + native `.xlsx` export. The Analytics dashboard and Logs
page must keep working with no visible regressions. The "test-a-link" page is
**out of scope** (shelved — see TODO.md #9).

> Project note (from prior sessions): addon Python code does **not** hot-reload —
> the proxy must be restarted to pick up changes. PowerShell `utf8` writes a BOM;
> all settings/policy loaders already use `utf-8-sig`. SQLite files are binary so
> BOM is a non-issue.

---

## Goals / acceptance criteria

1. Requests and blocks are written to `logs/webfilter.db` (SQLite, WAL mode).
2. Retention is **configurable** via `log_retention_days` (default `30`); rows
   older than the cutoff are pruned automatically. The old line-count cap
   (`request_log_max`) is gone.
3. Existing `logs/requests.jsonl` / `logs/blocks.jsonl` are imported once into the
   DB on first run, then set aside (renamed, not deleted).
4. `/api/analytics`, `/api/logs`, `/api/status` read from SQLite via indexed
   queries (bounded cost regardless of history depth) and return the **same JSON
   shapes** they do today.
5. New `GET /api/logs/export` streams a `.csv` or `.xlsx` of either log, within an
   optional time range.
6. Logs page gets an Export control; Settings page gets a "Log retention (days)"
   field.
7. Tests cover the store, aggregation, retention, migration, and export.

---

## Architecture

Two processes share `logs/` on one host (per CLAUDE.md). SQLite **WAL mode** lets
the proxy (single writer, runs in mitmproxy's asyncio main thread) and the
management API (readers, possibly across FastAPI threadpool threads) coexist
without blocking.

Concurrency rules for the new `shared/logstore.py`:
- **Writes** (proxy only) go through one module-level connection guarded by a
  `threading.Lock`. Safe because all proxy hook calls run on one thread.
- **Reads** (management API) open a fresh short-lived **read-only** connection per
  call (`sqlite3.connect("file:...?mode=ro", uri=True)`), so they are thread-safe
  under uvicorn's threadpool. If the DB file doesn't exist yet, reads return
  empty results.
- `busy_timeout=5000` on every connection to ride out brief lock contention.

---

## Phase 1 — `shared/logstore.py` (new file)

Single module owning the schema, writes, reads, aggregation, retention, and
migration. Public API:

```python
def configure(db_path: str, retention_days: int = 30,
              log_requests: bool = True, log_blocks: bool = True) -> None: ...
def migrate_legacy(logs_dir: str | Path) -> None: ...      # proxy only
def log_request(entry: dict) -> None: ...                   # proxy writer
def log_block(entry: dict) -> None: ...                     # proxy writer
def prune() -> None: ...                                     # delete ts < cutoff
def tail(kind: str, limit: int) -> list[dict]: ...          # newest-first
def analytics(start_ts: float) -> dict: ...                 # aggregation
def rows_in_range(kind: str, start_ts: int, end_ts: int) -> list[dict]: ...  # export
```

### Schema (created idempotently in `configure`)

```sql
CREATE TABLE IF NOT EXISTS requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  method TEXT, host TEXT, path TEXT,
  status INTEGER, action TEXT, component TEXT,
  policy TEXT, client_ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_requests_ts ON requests(ts);

CREATE TABLE IF NOT EXISTS blocks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  domain TEXT, url TEXT, reason TEXT,
  component TEXT, policy TEXT, client_ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_blocks_ts ON blocks(ts);
```

Column sets exactly mirror today's JSONL entries (see
[request_logger.py](../proxy/addons/request_logger.py) and
[block_page.py](../proxy/block_page.py) `log_block`).

### `configure`
- Store module state (`_db_path`, `_retention_days`, `_log_requests`,
  `_log_blocks`). `mkdir(parents=True)` the DB's parent.
- Open the persistent write connection; run `PRAGMA journal_mode=WAL;`
  `PRAGMA synchronous=NORMAL;` `PRAGMA busy_timeout=5000;`; execute the schema DDL.
- Call `prune()` once (startup cleanup). Idempotent — safe to call from both
  processes and on every restart.

### `log_request` / `log_block`
- No-op if the matching flag is off or `configure` was never called.
- `INSERT` the row under the lock. Use `entry.get(...)` with sensible defaults so a
  missing key never raises (matches the defensive feel of the current code).
- Maintain a module counter; every `_PRUNE_EVERY = 500` inserts call `prune()`
  (mirrors the old trim cadence, now time-based).

### `prune`
- `cutoff = int(time.time()) - retention_days * 86400`
- `DELETE FROM requests WHERE ts < ?` and same for `blocks`. Wrap in the lock.
- Guard `retention_days <= 0` → skip (treat as "keep everything").

### `tail(kind, limit)`
- Read-only connection. `SELECT ... FROM {table} ORDER BY ts DESC, id DESC LIMIT ?`.
- `kind`: `"requests"` or `"blocks"` (validate against a whitelist — never
  interpolate arbitrary table names). Return list of dicts newest-first (same as
  the old `_tail_jsonl`).

### `analytics(start_ts)`
Return the **exact dict** the current endpoint builds
([main.py:225-234](../management/api/main.py)). One read connection, these queries:

- `total_requests`: `SELECT COUNT(*) FROM requests WHERE ts >= ?`
- `total_blocks`: same on `blocks`
- `request_actions`: `SELECT action, COUNT(*) FROM requests WHERE ts>=? GROUP BY action`
- `top_blocked_domains`: `SELECT domain, COUNT(*) c FROM blocks WHERE ts>=? AND domain<>'' GROUP BY domain ORDER BY c DESC LIMIT 15`
- `blocks_by_component`: `SELECT component, COUNT(*) c FROM blocks WHERE ts>=? GROUP BY component ORDER BY c DESC` (coalesce empty component → `"unknown"`)
- `per_device`: `SELECT client_ip, COUNT(*) total, SUM(action='blocked') blocked, MAX(policy) policy FROM requests WHERE ts>=? GROUP BY client_ip ORDER BY total DESC` (map empty IP → `"unknown"`; today's code takes policy from an arbitrary row, so `MAX(policy)` is an acceptable equivalent)
- `blocks_timeline`: `SELECT (ts/3600)*3600 bucket, COUNT(*) c FROM blocks WHERE ts>=? GROUP BY bucket ORDER BY bucket` → `[{"ts": bucket, "count": c}]`
- Echo back `window_hours` — pass it in or compute from `start_ts`. Keep the field
  so the UI is unchanged.

### `rows_in_range(kind, start_ts, end_ts)`
- `SELECT * FROM {table} WHERE ts >= ? AND ts <= ? ORDER BY ts ASC`. Returns dicts
  with a stable column order (define `REQUEST_COLUMNS` / `BLOCK_COLUMNS` tuples and
  reuse them for export headers). Drop the internal `id` column from output.

### `migrate_legacy(logs_dir)` — proxy only
- For each of `requests.jsonl`→`requests`, `blocks.jsonl`→`blocks`:
  - Skip if the table is non-empty (`SELECT 1 ... LIMIT 1`) — prevents re-import.
  - Skip if the file is absent.
  - Read with `encoding="utf-8-sig"`, parse each line (ignore bad lines, like the
    current readers), bulk `INSERT` via `executemany`.
  - Rename the file to `<name>.imported` (non-destructive; reversible). If the
    rename target exists, append a timestamp.

---

## Phase 2 — settings & model

**[shared/models.py](../shared/models.py) `GlobalSettings`:**
- Add `log_retention_days: int = 30`.
- Remove `request_log_max` field and its only consumer. (Pydantic v2 ignores
  unknown keys by default, so leftover `request_log_max` in existing
  `settings.json` files is harmless.)
- Add derived property:
  ```python
  @property
  def db_path(self) -> str:
      return str(Path(self.logs_dir) / "webfilter.db")
  ```
  Keep `blocks_log_path` / `request_log_path` properties — `migrate_legacy` and the
  one-time import still reference the old filenames.

**[config/settings.example.json](../config/settings.example.json):** replace the
`"request_log_max": 2000` line with `"log_retention_days": 30`.

**[management/api/routes/settings.py](../management/api/routes/settings.py):** no
structural change needed — it round-trips the whole model — but verify the new
field survives a GET→PUT cycle.

---

## Phase 3 — proxy wiring

**[proxy/addons/policy_router.py](../proxy/addons/policy_router.py) `load()`:**
replace the two old init blocks with:

```python
from shared import logstore
if _settings.log_blocks or _settings.log_requests:
    logstore.configure(_settings.db_path, _settings.log_retention_days,
                       log_requests=_settings.log_requests,
                       log_blocks=_settings.log_blocks)
    logstore.migrate_legacy(_project_root / _settings.logs_dir.lstrip("./"))
```

**[proxy/addons/request_logger.py](../proxy/addons/request_logger.py):** change the
import to `from shared.logstore import log_request`. The entry dict is unchanged.

**[proxy/block_page.py](../proxy/block_page.py):**
- `init_logging()` → remove (or keep as a thin no-op shim if any caller remains;
  prefer removing and deleting the call). Keep the `flow.metadata["wf_action"]`/
  `["wf_component"]` marking exactly as-is.
- In `log_block`, after building `entry`, call `logstore.log_block(entry)` instead
  of writing JSONL. Drop the `_blocks_log` file handling.

**Delete [proxy/request_log.py](../proxy/request_log.py)** (fully superseded). Grep
for any other importers first.

---

## Phase 4 — management API

**[management/api/main.py](../management/api/main.py):**
- At startup (module load, after `_load_settings` is available) call
  `logstore.configure(settings.db_path, settings.log_retention_days, ...)` so reads
  have a schema even if the proxy hasn't started. Do **not** call `migrate_legacy`
  here (writer/proxy owns migration).
- `/api/status`: replace the two `_tail_jsonl(...)` calls with
  `logstore.tail("blocks", 50)` and `logstore.tail("requests", 100)`.
- `/api/logs`: return `{"kind": kind, "entries": logstore.tail(kind, limit)}`.
- `/api/analytics`: `cutoff = time.time() - hours*3600`; return
  `logstore.analytics(cutoff)` (pass `hours` through for `window_hours`).
- Remove the now-unused `_tail_jsonl` and `_read_all_jsonl` helpers.

**New endpoint — export:**

```python
@app.get("/api/logs/export")
def export_logs(kind: str = "requests", format: str = "csv",
                start: int | None = None, end: int | None = None):
```
- Validate `kind` ∈ {requests, blocks}; `format` ∈ {csv, xlsx}.
- `start = start or 0`; `end = end or int(time.time())`.
- `rows = logstore.rows_in_range(kind, start, end)`; columns from the shared tuple.
- Apply a safety cap (`MAX_EXPORT_ROWS = 500_000`) — if exceeded, return 400 asking
  for a narrower range (keeps memory/openpyxl bounded).
- **CSV:** build with stdlib `csv` into `io.StringIO`; return `Response` with
  `media_type="text/csv"` and
  `Content-Disposition: attachment; filename="{kind}-{YYYYMMDD-HHMMSS}.csv"`.
- **XLSX:** build with `openpyxl` (`Workbook`, header row + data rows) into
  `io.BytesIO`; `media_type=
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"`, same
  `Content-Disposition` pattern.
- Auth: the existing middleware already protects `/api/*` — no extra work. The
  download is a same-origin GET so the session cookie rides along.

---

## Phase 5 — dependencies

**[requirements.txt](../requirements.txt):** add under "Management API":
```
openpyxl>=3.1.0        # XLSX log export
```
`sqlite3` and `csv` are stdlib — nothing else needed.

---

## Phase 6 — UI

**[management/ui/logs.html](../management/ui/logs.html):** in the header controls
(next to Refresh), add:
- A format `<select>` (CSV / Excel) bound to `exportFormat`.
- Optional From/To `<input type="date">` bound to `exportFrom` / `exportTo`
  (blank = all).
- An **Export** button calling:
  ```js
  exportLogs() {
    const p = new URLSearchParams({ kind: this.tab, format: this.exportFormat });
    if (this.exportFrom) p.set('start', Math.floor(new Date(this.exportFrom).getTime()/1000));
    if (this.exportTo)   p.set('end',   Math.floor(new Date(this.exportTo + 'T23:59:59').getTime()/1000));
    window.location = '/api/logs/export?' + p.toString();
  }
  ```
  (Plain navigation triggers the browser download and sends the auth cookie.)
- Add the fields to the `logsPage()` `x-data` return.

**[management/ui/settings.html](../management/ui/settings.html):** add a number
input "Log retention (days)" bound to the settings model's `log_retention_days`,
in the same section as the other logging toggles (`log_blocks`/`log_requests`).
Remove any `request_log_max` control if one exists (grep first).

**[management/ui/i18n.js](../management/ui/i18n.js):** add keys for the new labels
(`logs.export`, `logs.exportFormat`, `logs.from`, `logs.to`,
`settings.logRetention`, etc.). English is the fallback, so other languages can be
filled later, but add the English entries at minimum.

---

## Phase 7 — tests

**New `tests/test_logstore.py`:**
- `configure` on a `tmp_path` DB; `log_request`/`log_block`; `tail` returns
  newest-first with correct fields.
- `analytics`: seed known rows, assert `total_requests`, `total_blocks`,
  `request_actions`, `top_blocked_domains` ordering, `per_device`
  totals/blocked/policy, and hourly `blocks_timeline` buckets.
- `prune`: insert rows older and newer than the cutoff; assert only old ones are
  deleted; assert `retention_days<=0` keeps everything.
- `rows_in_range`: boundary filtering (inclusive start/end).
- `migrate_legacy`: write sample `requests.jsonl`/`blocks.jsonl`, run migration,
  assert rows imported, files renamed to `.imported`, and a second run is a no-op
  (no duplicates).

**New `tests/test_export.py`** (FastAPI `TestClient`):
- Seed the DB (point settings/logstore at a temp DB), hit `/api/logs/export`:
  - CSV: response is `text/csv`, has the header row + N data rows, correct
    `Content-Disposition`.
  - XLSX: read the bytes back with `openpyxl.load_workbook(BytesIO(...))` and
    assert header + row count.
  - Over-cap range → 400.

**Update existing tests:**
- Delete `tests/test_request_log.py` (module removed).
- Grep tests for `request_log_max` / `_tail_jsonl` / `_read_all_jsonl` and update
  (e.g. `test_models.py` defaults/roundtrip — drop `request_log_max`, add
  `log_retention_days`; `test_settings_listen.py` if it references the field).

Run: `.venv/bin/pytest tests/ -v` (Windows: `.venv\Scripts\pytest tests\ -v`).

---

## Phase 8 — docs & housekeeping

- **CLAUDE.md**: update the "Request/Block Logging" section (now SQLite, retention
  by days, export endpoint) and the layout note for `proxy/request_log.py`
  (removed) + new `shared/logstore.py`.
- **.gitignore**: ensure `logs/` (or `logs/*.db*`) is ignored so the DB and its
  `-wal`/`-shm` sidecars aren't committed. (`logs/` is almost certainly already
  ignored — verify.)

---

## Migration & backward-compatibility notes

- First proxy start after deploy imports existing JSONL, then renames the files —
  no history lost, no double-import on later restarts.
- Old `settings.json` with `request_log_max` still loads (extra key ignored);
  `log_retention_days` defaults to 30 when absent.
- JSON shapes returned by `/api/analytics`, `/api/logs`, `/api/status` are
  unchanged, so `analytics.html` / `logs.html` / `index.html` need no logic change
  beyond the new export controls.

## Risks / watch-outs

- **WAL across processes** assumes `logs/` is local disk (true here). A network
  share would break WAL — note in CLAUDE.md if relevant.
- **openpyxl memory** for very large exports — mitigated by `MAX_EXPORT_ROWS`.
- **Proxy restart required** to load the new addon code (logging won't move to
  SQLite until the proxy is restarted). Call this out when verifying.

## Suggested commit slicing

1. `shared/logstore.py` + tests (no wiring yet).
2. model/settings change (`log_retention_days`, drop `request_log_max`, `db_path`).
3. proxy wiring (policy_router, request_logger, block_page; delete request_log.py).
4. management API reads switched to logstore + export endpoint + openpyxl dep.
5. UI (logs export controls, settings retention field, i18n).
6. docs (CLAUDE.md, this plan) + .gitignore.

## Manual verification

1. Restart proxy + management. Confirm `logs/webfilter.db` is created and any old
   `*.jsonl` became `*.jsonl.imported`.
2. Browse through the proxy to generate traffic + a block; confirm Logs page
   (both tabs) and Analytics populate.
3. Export CSV and XLSX for each tab; open in Excel; verify columns/rows and that a
   date range narrows the output.
4. Set retention to 1 day in Settings, restart proxy, confirm old rows prune.
