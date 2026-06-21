"""Tests for policy hot-reload via watchfiles.

Covers the Python 3.12 GC bug fix: the watch task must be held on `self` so it
isn't collected before it fires.  Also verifies the watcher retries after an
error instead of dying silently.

All async code is driven via asyncio.run() to avoid requiring pytest-asyncio.
"""
import asyncio
import gc
import json
import sys
import types
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import proxy.addons.policy_router as pr
from proxy.addons.policy_router import PolicyRouter
from shared.models import Policy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_policy(name="test", source_ips=None) -> Policy:
    return Policy(name=name, source_ips=source_ips or [])


def _router_with_stubs(monkeypatch, tmp_path):
    """Return a PolicyRouter with running() stubs in place (no mitmproxy ctx)."""
    router = PolicyRouter()
    monkeypatch.setattr(pr, "_settings", pr.GlobalSettings())
    monkeypatch.setattr(pr, "_policies", [])
    monkeypatch.setattr(pr, "load_settings", lambda: pr.GlobalSettings())
    monkeypatch.setattr(pr, "load_policies", lambda d: [])
    monkeypatch.setattr(pr, "_project_root", tmp_path)
    monkeypatch.setattr(router, "_sync_ignore_hosts", lambda: None)
    return router


# ---------------------------------------------------------------------------
# Task-reference tests (the GC-safety fix)
# ---------------------------------------------------------------------------

class TestWatchTaskReference:
    """_watch_task must be stored on self so Python 3.12 GC can't collect it."""

    def test_task_stored_on_self(self, tmp_path, monkeypatch):
        """running() must set self._watch_task to a live Task object."""
        async def _run():
            router = _router_with_stubs(monkeypatch, tmp_path)

            async def _long_watch(policies_dir):
                await asyncio.sleep(9999)

            monkeypatch.setattr(router, "_watch", _long_watch)
            router.running()
            await asyncio.sleep(0)  # let the event loop schedule the task

            assert hasattr(router, "_watch_task"), "_watch_task not set on router"
            task = router._watch_task
            assert isinstance(task, asyncio.Task)
            assert not task.done(), "watch task exited immediately"

            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

        asyncio.run(_run())

    def test_task_survives_gc(self, tmp_path, monkeypatch):
        """With a stored reference the task must not be collected/cancelled by GC."""
        async def _run():
            router = _router_with_stubs(monkeypatch, tmp_path)

            async def _long_watch(policies_dir):
                await asyncio.sleep(9999)

            monkeypatch.setattr(router, "_watch", _long_watch)
            router.running()
            await asyncio.sleep(0)

            gc.collect()
            await asyncio.sleep(0)

            assert not router._watch_task.done(), (
                "watch task was collected/cancelled — strong reference missing"
            )

            router._watch_task.cancel()
            try:
                await router._watch_task
            except (asyncio.CancelledError, Exception):
                pass

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# Retry-on-error tests
# ---------------------------------------------------------------------------

class TestWatchRetry:
    """_watch() must restart the awatch loop after a non-CancelledError exception."""

    def test_retries_after_error(self, tmp_path, monkeypatch):
        """If awatch raises RuntimeError, the watcher should sleep and restart."""
        calls = []
        sleep_args = []

        # Capture real sleep before we patch it.
        _real_sleep = asyncio.sleep

        async def _fast_sleep(n):
            sleep_args.append(n)
            await _real_sleep(0)  # yield control without actually waiting

        monkeypatch.setattr(pr.asyncio, "sleep", _fast_sleep)

        async def _run():
            retried = asyncio.Event()
            block = asyncio.Event()  # never set; blocks second awatch until cancel

            async def _crashing_awatch(path, **kw):
                calls.append(len(calls) + 1)
                if len(calls) == 1:
                    raise RuntimeError("simulated watcher crash")
                # Second iteration: signal test, then block until cancelled.
                retried.set()
                await block.wait()
                return
                yield  # mark as async generator

            fake_wf = types.ModuleType("watchfiles")
            fake_wf.awatch = _crashing_awatch
            monkeypatch.setitem(sys.modules, "watchfiles", fake_wf)

            router = PolicyRouter()
            monkeypatch.setattr(router, "_sync_ignore_hosts", lambda: None)
            monkeypatch.setattr(pr, "load_policies", lambda d: [_make_policy("r")])

            task = asyncio.create_task(router._watch(tmp_path))
            await asyncio.wait_for(retried.wait(), timeout=2)
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

        asyncio.run(_run())

        assert len(calls) == 2, f"expected crash + retry (2 calls), got {calls}"
        assert sleep_args, "expected asyncio.sleep() called between retries"

    def test_cancelled_propagates(self, tmp_path, monkeypatch):
        """CancelledError must propagate out of _watch, not be swallowed."""
        async def _blocking_awatch(path, **kw):
            await asyncio.sleep(9999)
            return
            yield  # make it a valid async generator

        fake_watchfiles = types.ModuleType("watchfiles")
        fake_watchfiles.awatch = _blocking_awatch
        monkeypatch.setitem(sys.modules, "watchfiles", fake_watchfiles)

        async def _run():
            router = PolicyRouter()
            monkeypatch.setattr(router, "_sync_ignore_hosts", lambda: None)

            task = asyncio.create_task(router._watch(tmp_path))
            await asyncio.sleep(0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# End-to-end: actual filesystem change triggers reload
# ---------------------------------------------------------------------------

class TestWatchReloadsOnChange:
    """Writing a new policy JSON while _watch runs must update pr._policies."""

    def test_reload_on_file_change(self, tmp_path):
        pytest.importorskip("watchfiles")

        policies_dir = tmp_path / "policies"
        policies_dir.mkdir()

        (policies_dir / "p1.json").write_text(
            json.dumps({"name": "p1", "source_ips": []}), encoding="utf-8"
        )
        pr._policies = pr.load_policies(policies_dir)
        assert len(pr._policies) == 1

        async def _run():
            router = PolicyRouter()
            router._sync_ignore_hosts = lambda: None

            task = asyncio.create_task(router._watch(policies_dir))
            await asyncio.sleep(0.1)  # let awatch start

            (policies_dir / "p2.json").write_text(
                json.dumps({"name": "p2", "source_ips": ["10.0.0.1"]}),
                encoding="utf-8",
            )

            for _ in range(30):
                await asyncio.sleep(0.1)
                if len(pr._policies) == 2:
                    break

            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

            assert len(pr._policies) == 2, (
                "Hot-reload did not pick up the new policy file"
            )

        asyncio.run(_run())
