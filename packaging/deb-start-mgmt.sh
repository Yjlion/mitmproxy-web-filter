#!/usr/bin/env bash
# Launched by webfilter-mgmt.service. Reads mgmt_host/mgmt_port from settings.
set -euo pipefail
cd /opt/webfilter-proxy

PY=./venv/bin/python3

read -r MGMT_HOST MGMT_PORT <<< "$($PY -c "
import sys; sys.path.insert(0, '.')
from pathlib import Path
from shared.models import GlobalSettings
p = Path('config/settings.json')
s = GlobalSettings.model_validate_json(p.read_text()) if p.exists() else GlobalSettings()
print(s.mgmt_host, s.mgmt_port)
")"

exec $PY -m uvicorn management.api.main:app \
    --host "$MGMT_HOST" \
    --port "$MGMT_PORT" \
    --log-level warning
