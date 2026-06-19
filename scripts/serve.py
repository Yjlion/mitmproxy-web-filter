#!/usr/bin/env python3
"""Cross-platform launcher for the management UI + filtering proxy.

start.bat / start.sh select an interpreter and run this with it, so the same
logic works with a bundled runtime, a dev virtualenv, or system Python. Doing
the work in Python (instead of in batch/shell) avoids cmd.exe quoting pitfalls
and keeps the two platforms in sync.

Reads config/settings.json through the shared model (so legacy and IPv6 listen
forms resolve correctly), starts the FastAPI management server and mitmproxy,
opens the management UI in a browser, and shuts both down cleanly on exit.
"""
import os
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))

from shared.models import GlobalSettings


def load_settings() -> GlobalSettings:
    p = Path("config/settings.json")
    if p.exists():
        return GlobalSettings.model_validate_json(p.read_text(encoding="utf-8-sig"))
    return GlobalSettings()


def main() -> int:
    s = load_settings()
    py = sys.executable

    proxy_mode_args: list[str] = []
    for m in s.proxy_modes:
        proxy_mode_args += ["--mode", m]

    print()
    print("  WebFilter Proxy")
    print("  ===============================")
    print(f"  Proxy listen: {', '.join(s.proxy_listen)}")
    print(f"  Management:   http://{s.mgmt_host}:{s.mgmt_port}")
    print("  Press Ctrl+C to stop")
    print("  ===============================")
    print()

    # On Windows, give the management UI its own console window (matches the
    # original two-window behaviour); on other platforms it shares stdout.
    mgmt_kwargs = {}
    if os.name == "nt":
        mgmt_kwargs["creationflags"] = subprocess.CREATE_NEW_CONSOLE

    mgmt = subprocess.Popen(
        [py, "-m", "uvicorn", "management.api.main:app",
         "--host", s.mgmt_host, "--port", str(s.mgmt_port),
         "--log-level", "warning"],
        **mgmt_kwargs,
    )

    # Open the browser once management has had a moment to bind.
    def _open_browser() -> None:
        time.sleep(2)
        try:
            webbrowser.open(f"http://localhost:{s.mgmt_port}")
        except Exception:
            pass

    threading.Thread(target=_open_browser, daemon=True).start()

    upstream_args: list[str] = []
    if s.upstream_auth.strip():
        upstream_args += ["--set", f"upstream_auth={s.upstream_auth.strip()}"]

    # Run the proxy in the foreground (its logs stay in this window).
    proxy = subprocess.Popen(
        [py, "scripts/run_proxy.py",
         "--set", "confdir=./certs",
         *proxy_mode_args,
         *upstream_args,
         "-s", "proxy/main.py",
         "--set", "block_global=false"],
    )

    rc = 0
    try:
        rc = proxy.wait()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        for p in (proxy, mgmt):
            if p.poll() is None:
                try:
                    p.terminate()
                except Exception:
                    pass
        for p in (proxy, mgmt):
            try:
                p.wait(timeout=10)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        print("Stopped.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
