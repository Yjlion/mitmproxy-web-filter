"""Tests for shared/logstore.py — SQLite log store."""
from __future__ import annotations

import importlib
import json
import sys
import time
from pathlib import Path

import pytest

# Ensure the repo root is on sys.path so `shared` is importable.
sys.path.insert(0, str(Path(__file__).parent.parent))

import shared.logstore as ls


def _reset(db_path: str, retention_days: int = 30) -> None:
    """Re-configure the module so each test gets a fresh connection."""
    # Close any open write connection from a previous test.
    if ls._conn is not None:
        try:
            ls._conn.close()
        except Exception:
            pass
        ls._conn = None
    ls._db_path = None
    ls._insert_count = 0
    ls.configure(db_path, retention_days=retention_days)


class TestConfigure:
    def test_creates_db_and_tables(self, tmp_path):
        db = str(tmp_path / "wf.db")
        _reset(db)
        # Both tables must exist.
        conn = ls._open_read_conn(db)
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        conn.close()
        assert "requests" in tables
        assert "blocks" in tables

    def test_idempotent(self, tmp_path):
        db = str(tmp_path / "wf.db")
        _reset(db)
        _reset(db)  # second call must not raise


class TestLogAndTail:
    def test_log_request_appears_in_tail(self, tmp_path):
        _reset(str(tmp_path / "wf.db"))
        ls.log_request({
            "ts": 1_000_000, "method": "GET", "host": "example.com",
            "path": "/", "status": 200, "action": "ok",
            "component": "", "policy": "default", "client_ip": "10.0.0.1",
        })
        rows = ls.tail("requests", 10)
        assert len(rows) == 1
        assert rows[0]["host"] == "example.com"
        assert "id" not in rows[0]

    def test_tail_newest_first(self, tmp_path):
        _reset(str(tmp_path / "wf.db"))
        for i in range(5):
            ls.log_request({"ts": i, "host": f"h{i}.com", "action": "ok"})
        rows = ls.tail("requests", 10)
        assert rows[0]["ts"] >= rows[-1]["ts"]

    def test_log_block_appears_in_tail(self, tmp_path):
        _reset(str(tmp_path / "wf.db"))
        ls.log_block({
            "ts": 2_000_000, "domain": "bad.com", "url": "https://bad.com/",
            "reason": "blocklist", "component": "url_filter",
            "policy": "kids", "client_ip": "192.168.1.5",
        })
        rows = ls.tail("blocks", 10)
        assert len(rows) == 1
        assert rows[0]["domain"] == "bad.com"

    def test_tail_limit_respected(self, tmp_path):
        _reset(str(tmp_path / "wf.db"))
        for i in range(20):
            ls.log_request({"ts": i, "host": f"h{i}.com", "action": "ok"})
        rows = ls.tail("requests", 5)
        assert len(rows) == 5

    def test_tail_empty_db_returns_empty(self, tmp_path):
        _reset(str(tmp_path / "wf.db"))
        assert ls.tail("requests", 100) == []
        assert ls.tail("blocks", 100) == []

    def test_tail_invalid_kind_raises(self, tmp_path):
        _reset(str(tmp_path / "wf.db"))
        with pytest.raises(ValueError):
            ls.tail("bad_table", 10)

    def test_no_configure_tail_returns_empty(self):
        # Temporarily clear module state.
        original = ls._db_path
        ls._db_path = None
        try:
            assert ls.tail("requests", 10) == []
        finally:
            ls._db_path = original


class TestAnalytics:
    def _seed(self):
        now = int(time.time())
        # 3 requests: 2 ok, 1 blocked
        ls.log_request({"ts": now - 60, "host": "a.com", "action": "ok",
                        "client_ip": "10.0.0.1", "policy": "default",
                        "method": "GET", "path": "/", "status": 200, "component": ""})
        ls.log_request({"ts": now - 50, "host": "b.com", "action": "ok",
                        "client_ip": "10.0.0.1", "policy": "default",
                        "method": "GET", "path": "/", "status": 200, "component": ""})
        ls.log_request({"ts": now - 40, "host": "bad.com", "action": "blocked",
                        "client_ip": "10.0.0.2", "policy": "kids",
                        "method": "GET", "path": "/", "status": 200, "component": "url_filter"})
        # 2 blocks
        ls.log_block({"ts": now - 40, "domain": "bad.com", "url": "https://bad.com/",
                      "reason": "blocklist", "component": "url_filter",
                      "policy": "kids", "client_ip": "10.0.0.2"})
        ls.log_block({"ts": now - 30, "domain": "bad.com", "url": "https://bad.com/x",
                      "reason": "blocklist", "component": "url_filter",
                      "policy": "kids", "client_ip": "10.0.0.2"})
        return now

    def test_totals(self, tmp_path):
        _reset(str(tmp_path / "wf.db"))
        now = self._seed()
        result = ls.analytics(now - 3600, window_hours=1)
        assert result["total_requests"] == 3
        assert result["total_blocks"] == 2

    def test_request_actions(self, tmp_path):
        _reset(str(tmp_path / "wf.db"))
        self._seed()
        result = ls.analytics(time.time() - 3600)
        assert result["request_actions"].get("ok") == 2
        assert result["request_actions"].get("blocked") == 1

    def test_top_blocked_domains(self, tmp_path):
        _reset(str(tmp_path / "wf.db"))
        self._seed()
        result = ls.analytics(time.time() - 3600)
        assert result["top_blocked_domains"][0]["domain"] == "bad.com"
        assert result["top_blocked_domains"][0]["count"] == 2

    def test_per_device(self, tmp_path):
        _reset(str(tmp_path / "wf.db"))
        self._seed()
        result = ls.analytics(time.time() - 3600)
        by_ip = {d["ip"]: d for d in result["per_device"]}
        assert by_ip["10.0.0.1"]["total"] == 2
        assert by_ip["10.0.0.1"]["blocked"] == 0
        assert by_ip["10.0.0.2"]["total"] == 1
        assert by_ip["10.0.0.2"]["blocked"] == 1

    def test_blocks_timeline_buckets(self, tmp_path):
        _reset(str(tmp_path / "wf.db"))
        self._seed()
        result = ls.analytics(time.time() - 3600)
        assert len(result["blocks_timeline"]) >= 1
        assert all("ts" in e and "count" in e for e in result["blocks_timeline"])

    def test_window_hours_echoed(self, tmp_path):
        _reset(str(tmp_path / "wf.db"))
        result = ls.analytics(time.time() - 3600, window_hours=42)
        assert result["window_hours"] == 42

    def test_empty_db_returns_zeros(self, tmp_path):
        _reset(str(tmp_path / "wf.db"))
        result = ls.analytics(time.time() - 3600)
        assert result["total_requests"] == 0
        assert result["total_blocks"] == 0


class TestPrune:
    def test_prune_deletes_old_rows(self, tmp_path):
        _reset(str(tmp_path / "wf.db"), retention_days=1)
        now = int(time.time())
        old_ts = now - 2 * 86400   # 2 days ago — beyond 1-day retention
        new_ts = now - 3600        # 1 hour ago — within retention

        ls.log_request({"ts": old_ts, "host": "old.com", "action": "ok"})
        ls.log_request({"ts": new_ts, "host": "new.com", "action": "ok"})
        ls.log_block({"ts": old_ts, "domain": "old.com"})
        ls.log_block({"ts": new_ts, "domain": "new.com"})

        ls.prune()

        req_rows = ls.tail("requests", 100)
        blk_rows = ls.tail("blocks", 100)
        assert all(r["host"] == "new.com" for r in req_rows)
        assert all(r["domain"] == "new.com" for r in blk_rows)

    def test_retention_zero_keeps_everything(self, tmp_path):
        _reset(str(tmp_path / "wf.db"), retention_days=0)
        old_ts = int(time.time()) - 365 * 86400
        ls.log_request({"ts": old_ts, "host": "ancient.com", "action": "ok"})
        ls.prune()  # should be a no-op
        assert len(ls.tail("requests", 100)) == 1


class TestRowsInRange:
    def test_boundary_inclusive(self, tmp_path):
        _reset(str(tmp_path / "wf.db"))
        for ts in [100, 200, 300, 400, 500]:
            ls.log_request({"ts": ts, "host": f"h{ts}.com", "action": "ok"})
        rows = ls.rows_in_range("requests", 200, 400)
        tss = [r["ts"] for r in rows]
        assert 100 not in tss
        assert 200 in tss
        assert 400 in tss
        assert 500 not in tss

    def test_ordered_asc(self, tmp_path):
        _reset(str(tmp_path / "wf.db"))
        for ts in [300, 100, 200]:
            ls.log_request({"ts": ts, "host": f"h{ts}.com", "action": "ok"})
        rows = ls.rows_in_range("requests", 0, 9999)
        tss = [r["ts"] for r in rows]
        assert tss == sorted(tss)

    def test_no_id_column(self, tmp_path):
        _reset(str(tmp_path / "wf.db"))
        ls.log_request({"ts": 1, "host": "x.com", "action": "ok"})
        rows = ls.rows_in_range("requests", 0, 9999)
        assert "id" not in rows[0]


class TestMigrateLegacy:
    def test_imports_jsonl_and_renames(self, tmp_path):
        db = str(tmp_path / "wf.db")
        _reset(db)

        req_file = tmp_path / "requests.jsonl"
        blk_file = tmp_path / "blocks.jsonl"

        req_file.write_text(
            json.dumps({"ts": 1000, "method": "GET", "host": "a.com",
                        "path": "/", "status": 200, "action": "ok",
                        "component": "", "policy": "p", "client_ip": "1.2.3.4"}) + "\n",
            encoding="utf-8",
        )
        blk_file.write_text(
            json.dumps({"ts": 2000, "domain": "bad.com", "url": "https://bad.com/",
                        "reason": "test", "component": "url_filter",
                        "policy": "p", "client_ip": "1.2.3.4"}) + "\n",
            encoding="utf-8",
        )

        ls.migrate_legacy(tmp_path)

        # Rows imported.
        reqs = ls.tail("requests", 10)
        blks = ls.tail("blocks", 10)
        assert len(reqs) == 1
        assert reqs[0]["host"] == "a.com"
        assert len(blks) == 1
        assert blks[0]["domain"] == "bad.com"

        # Files renamed.
        assert not req_file.exists()
        assert not blk_file.exists()
        assert (tmp_path / "requests.jsonl.imported").exists()
        assert (tmp_path / "blocks.jsonl.imported").exists()

    def test_no_duplicate_on_second_run(self, tmp_path):
        db = str(tmp_path / "wf.db")
        _reset(db)

        req_file = tmp_path / "requests.jsonl"
        req_file.write_text(
            json.dumps({"ts": 1000, "host": "a.com", "action": "ok"}) + "\n",
            encoding="utf-8",
        )

        ls.migrate_legacy(tmp_path)
        # First run imports 1 row and renames file.
        assert len(ls.tail("requests", 100)) == 1

        # Write a new file (simulating re-deploy scenario, but table is non-empty).
        new_file = tmp_path / "requests.jsonl"
        new_file.write_text(
            json.dumps({"ts": 9999, "host": "b.com", "action": "ok"}) + "\n",
            encoding="utf-8",
        )
        ls.migrate_legacy(tmp_path)
        # Second run must be a no-op (table already has rows).
        assert len(ls.tail("requests", 100)) == 1

    def test_missing_files_skipped(self, tmp_path):
        db = str(tmp_path / "wf.db")
        _reset(db)
        # No jsonl files present — should not raise.
        ls.migrate_legacy(tmp_path)
        assert ls.tail("requests", 10) == []

    def test_bom_tolerant(self, tmp_path):
        db = str(tmp_path / "wf.db")
        _reset(db)
        req_file = tmp_path / "requests.jsonl"
        req_file.write_text(
            json.dumps({"ts": 5000, "host": "bom.com", "action": "ok"}) + "\n",
            encoding="utf-8-sig",  # BOM-encoded, like PowerShell output
        )
        ls.migrate_legacy(tmp_path)
        assert ls.tail("requests", 10)[0]["host"] == "bom.com"


# ---------------------------------------------------------------------------
# Tests: user_agent column (A4)
# ---------------------------------------------------------------------------

class TestUserAgentColumn:
    def test_user_agent_round_trips(self, tmp_path):
        """user_agent written via log_request must appear in tail()."""
        _reset(str(tmp_path / "wf.db"))
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TestBrowser/1.0"
        ls.log_request({
            "ts": 1_000_000,
            "method": "GET",
            "host": "example.com",
            "path": "/",
            "status": 200,
            "action": "ok",
            "component": "",
            "policy": "default",
            "client_ip": "10.0.0.1",
            "user_agent": ua,
        })
        rows = ls.tail("requests", 10)
        assert len(rows) == 1
        assert rows[0]["user_agent"] == ua

    def test_migration_adds_user_agent_column(self, tmp_path):
        """configure() on a DB whose requests table lacks user_agent must add it.

        Steps:
          1. Create the table WITHOUT user_agent (simulating a pre-migration DB).
          2. Call configure() — this must run the ALTER TABLE migration.
          3. Assert the column exists and a row with user_agent can be inserted
             and read back.
        """
        import sqlite3

        db = str(tmp_path / "wf.db")

        # Step 1: Create the old-schema table (no user_agent column).
        conn = sqlite3.connect(db)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS requests (
              id        INTEGER PRIMARY KEY AUTOINCREMENT,
              ts        INTEGER NOT NULL,
              method    TEXT,
              host      TEXT,
              path      TEXT,
              status    INTEGER,
              action    TEXT,
              component TEXT,
              policy    TEXT,
              client_ip TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS blocks (
              id        INTEGER PRIMARY KEY AUTOINCREMENT,
              ts        INTEGER NOT NULL,
              domain    TEXT,
              url       TEXT,
              reason    TEXT,
              component TEXT,
              policy    TEXT,
              client_ip TEXT
            )
        """)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.commit()
        conn.close()

        # Step 2: configure() must run the migration.
        if ls._conn is not None:
            try:
                ls._conn.close()
            except Exception:
                pass
            ls._conn = None
        ls._db_path = None
        ls._insert_count = 0
        ls.configure(db, retention_days=0)

        # Step 3a: Verify the column exists via PRAGMA.
        read_conn = ls._open_read_conn(db)
        cols = {row[1] for row in read_conn.execute("PRAGMA table_info(requests)").fetchall()}
        read_conn.close()
        assert "user_agent" in cols

        # Step 3b: Insert a row with user_agent and read it back.
        ls.log_request({
            "ts": 9_000_000,
            "method": "GET",
            "host": "migrated.example.com",
            "path": "/",
            "status": 200,
            "action": "ok",
            "component": "",
            "policy": "p",
            "client_ip": "192.168.1.1",
            "user_agent": "MigrationTestAgent/1.0",
        })
        rows = ls.tail("requests", 10)
        assert any(r.get("user_agent") == "MigrationTestAgent/1.0" for r in rows)
