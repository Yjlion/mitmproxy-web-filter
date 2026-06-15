#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Pick a Python interpreter: a bundled runtime (in release archives), else the
# dev virtualenv, else system Python.
if [[ -x "runtime/bin/python3" ]]; then
    PY="runtime/bin/python3"
elif [[ -x ".venv/bin/python" ]]; then
    PY=".venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PY="python3"
else
    echo "[error] No Python runtime found (expected ./runtime, ./.venv, or system python3). Run ./install.sh first."
    exit 1
fi

# Raise the open-file limit. mitmproxy holds 2 file descriptors per connection
# (client + upstream); browsers open many parallel connections, so the default
# soft limit of 1024 is exhausted quickly ("Too many open files").
HARD_NOFILE=$(ulimit -Hn)
TARGET_NOFILE=65536
if [[ "$HARD_NOFILE" != "unlimited" && "$HARD_NOFILE" -lt "$TARGET_NOFILE" ]]; then
    TARGET_NOFILE=$HARD_NOFILE
fi
if ! ulimit -Sn "$TARGET_NOFILE" 2>/dev/null; then
    echo "[warn] Could not raise open-file limit (current soft: $(ulimit -Sn))."
else
    echo "[info] Open-file limit set to $(ulimit -Sn)"
fi

# Resolve listen settings via the model (handles legacy configs + IPv6 forms).
eval "$("$PY" - <<'PY'
import json, sys
sys.path.insert(0, '.')
from pathlib import Path
from shared.models import GlobalSettings
p = Path('config/settings.json')
s = GlobalSettings.model_validate_json(p.read_text()) if p.exists() else GlobalSettings()
print(f"PROXY_MODES={json.dumps(' '.join('--mode ' + m for m in s.proxy_modes))}")
print(f"PROXY_DESC={json.dumps(', '.join(s.proxy_listen))}")
print(f"MGMT_HOST={json.dumps(s.mgmt_host)}")
print(f"MGMT_PORT={s.mgmt_port}")
PY
)"

cleanup() {
    echo ""
    echo "Shutting down..."
    [[ -n "${MITM_PID:-}" ]] && kill "$MITM_PID" 2>/dev/null || true
    [[ -n "${MGMT_PID:-}" ]] && kill "$MGMT_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    echo "Stopped."
}
trap cleanup SIGINT SIGTERM EXIT

echo ""
echo "  WebFilter Proxy"
echo "  ==============================="
echo "  Proxy listen: $PROXY_DESC"
echo "  Management:   http://$MGMT_HOST:$MGMT_PORT"
echo "  Press Ctrl+C to stop"
echo "  ==============================="
echo ""

# Start management API
"$PY" -m uvicorn management.api.main:app \
    --host "$MGMT_HOST" \
    --port "$MGMT_PORT" \
    --log-level warning &
MGMT_PID=$!

sleep 1

# Start mitmproxy with one --mode per configured listen endpoint.
"$PY" scripts/run_proxy.py \
    --set confdir=./certs \
    $PROXY_MODES \
    -s proxy/main.py \
    --set block_global=false &
MITM_PID=$!

wait
