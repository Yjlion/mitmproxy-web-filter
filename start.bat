@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"

:: Pick a Python interpreter: bundled runtime (release archive), else dev venv, else system.
if exist "runtime\python.exe" (
    set "PY=runtime\python.exe"
) else if exist ".venv\Scripts\python.exe" (
    set "PY=.venv\Scripts\python.exe"
) else (
    where python >nul 2>&1 && set "PY=python"
)
if not defined PY (
    echo [error] No Python runtime found (expected runtime\, .venv\, or system python). Run install.bat first.
    pause & exit /b 1
)

:: Resolve listen settings via the model (handles legacy configs + IPv6 forms).
for /f "delims=" %%m in ('"%PY%" -c "import sys;sys.path.insert(0,'.');from shared.models import GlobalSettings as G;from pathlib import Path as P;p=P('config/settings.json');s=G.model_validate_json(p.read_text()) if p.exists() else G();print(' '.join('--mode '+m for m in s.proxy_modes))" 2^>nul') do set "PROXY_MODES=%%m"

for /f "delims=" %%h in ('"%PY%" -c "import sys;sys.path.insert(0,'.');from shared.models import GlobalSettings as G;from pathlib import Path as P;p=P('config/settings.json');s=G.model_validate_json(p.read_text()) if p.exists() else G();print(s.mgmt_host)" 2^>nul') do set "MGMT_HOST=%%h"
if not defined MGMT_HOST set MGMT_HOST=0.0.0.0

for /f "delims=" %%p in ('"%PY%" -c "import sys;sys.path.insert(0,'.');from shared.models import GlobalSettings as G;from pathlib import Path as P;p=P('config/settings.json');s=G.model_validate_json(p.read_text()) if p.exists() else G();print(s.mgmt_port)" 2^>nul') do set "MGMT_PORT=%%p"
if not defined MGMT_PORT set MGMT_PORT=8000

echo.
echo   WebFilter Proxy
echo   ===============================
echo   Proxy modes:  %PROXY_MODES%
echo   Management:   http://%MGMT_HOST%:%MGMT_PORT%
echo   Close this window to stop.
echo   ===============================
echo.

:: Start management UI in its own window
start "WebFilter Management" "%PY%" -m uvicorn management.api.main:app --host %MGMT_HOST% --port %MGMT_PORT% --log-level warning

:: Give management a moment to start
timeout /t 2 /nobreak >nul

:: Open browser
start "" "http://localhost:%MGMT_PORT%"

:: Start proxy in this window (keeps it visible for logs)
"%PY%" scripts\run_proxy.py --set confdir=./certs %PROXY_MODES% -s proxy/main.py --set block_global=false

echo Proxy stopped.
pause
