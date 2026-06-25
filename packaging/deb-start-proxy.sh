#!/usr/bin/env bash
# Launched by webfilter-proxy.service. Reads proxy_listen from settings.json
# and builds the --mode args dynamically so the service respects config changes.
set -euo pipefail
cd /opt/webfilter-proxy

PY=./venv/bin/python3

# Build --mode flags from settings (handles regular, socks5, transparent, dns, …)
PROXY_MODES="$($PY -c "
import sys; sys.path.insert(0, '.')
from pathlib import Path
from shared.models import GlobalSettings
p = Path('config/settings.json')
s = GlobalSettings.model_validate_json(p.read_text()) if p.exists() else GlobalSettings()
print(' '.join('--mode ' + m for m in s.proxy_modes))
")"

# Raise the open-file limit (systemd LimitNOFILE does this too, but belt-and-
# suspenders in case the service file wasn't applied yet after install).
ulimit -Sn 65536 2>/dev/null || true

exec $PY scripts/run_proxy.py \
    --set confdir=/var/lib/webfilter-proxy/certs \
    $PROXY_MODES \
    -s proxy/main.py \
    --set block_global=false
