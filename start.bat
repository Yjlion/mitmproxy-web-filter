@echo off
setlocal
cd /d "%~dp0"

:: Pick a Python interpreter: bundled runtime (release archive), else dev venv, else system.
set "PY="
if exist "runtime\python.exe" (
    set "PY=runtime\python.exe"
) else if exist ".venv\Scripts\python.exe" (
    set "PY=.venv\Scripts\python.exe"
) else (
    where python >nul 2>&1 && set "PY=python"
)
if not defined PY (
    echo [error] No Python runtime found. Expected runtime\, .venv\, or a system python. Run install.bat first.
    pause
    exit /b 1
)

:: All launch logic lives in serve.py to avoid cmd.exe quoting pitfalls.
"%PY%" scripts\serve.py

pause
