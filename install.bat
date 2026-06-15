@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"

echo.
echo   WebFilter Proxy -- Installer
echo   ================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [error] Python not found. Install Python 3.10+ from https://python.org
    echo         Make sure to check "Add Python to PATH" during installation.
    pause & exit /b 1
)

for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PY_VERSION=%%v
for /f "tokens=1,2 delims=." %%a in ("!PY_VERSION!") do (
    set PY_MAJOR=%%a
    set PY_MINOR=%%b
)
if !PY_MAJOR! LSS 3 (
    echo [error] Python !PY_VERSION! found, but 3.10+ is required.
    pause & exit /b 1
)
if !PY_MAJOR! EQU 3 if !PY_MINOR! LSS 10 (
    echo [error] Python !PY_VERSION! found, but 3.10+ is required.
    pause & exit /b 1
)
echo [ok]   Python !PY_VERSION! found

:: Create virtual environment
if not exist ".venv\" (
    echo [info] Creating virtual environment...
    python -m venv .venv
    echo [ok]   Virtual environment created
) else (
    echo [info] Virtual environment already exists
)

:: Install dependencies
echo [info] Installing dependencies (this may take a few minutes^)...
.venv\Scripts\pip install --upgrade pip -q
.venv\Scripts\pip install -r requirements.txt
echo [ok]   Dependencies installed

:: Create directories
if not exist "certs\" mkdir certs
if not exist "logs\"  mkdir logs
if not exist "models\" mkdir models
echo [info] Directories created: certs\ logs\ models\

:: Generate mitmproxy CA certificate
echo [info] Generating CA certificate...
start /b "" .venv\Scripts\mitmdump.exe --set confdir=./certs -q --mode regular --listen-port 18080
timeout /t 4 /nobreak >nul
taskkill /f /im mitmdump.exe >nul 2>&1
timeout /t 1 /nobreak >nul

if exist "certs\mitmproxy-ca-cert.cer" (
    echo [ok]   CA certificate generated: certs\mitmproxy-ca-cert.cer
    echo.
    set /p INSTALL_CERT="Install CA cert to Windows trust store? (requires admin) [y/N]: "
    if /i "!INSTALL_CERT!"=="y" (
        certutil -addstore -f "Root" "certs\mitmproxy-ca-cert.cer" >nul 2>&1
        if errorlevel 1 (
            echo [warn]  Could not auto-install cert. Right-click certs\mitmproxy-ca-cert.cer ^> Install Certificate.
        ) else (
            echo [ok]   CA cert installed to Windows trust store
        )
    )
) else if exist "certs\mitmproxy-ca-cert.pem" (
    echo [ok]   CA certificate generated: certs\mitmproxy-ca-cert.pem
) else (
    echo [warn]  CA cert not generated -- it will be created on first proxy start
)

echo.
echo   ============================================
echo   Installation complete!
echo.
echo   Next steps:
echo     1. Run:  start.bat
echo     2. Open: http://localhost:8000  (management UI)
echo     3. Configure browser proxy: 127.0.0.1:8080
echo     4. Install CA cert if not done above
echo   ============================================
echo.
pause
