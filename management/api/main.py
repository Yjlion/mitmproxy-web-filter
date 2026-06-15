from __future__ import annotations
import json
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from fastapi import FastAPI, Request, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse

from management.api.routes import policies, settings as settings_router
from management.api import auth
from shared.models import GlobalSettings

_ROOT = Path(__file__).parent.parent.parent
_SETTINGS_PATH = _ROOT / "config" / "settings.json"

app = FastAPI(title="WebFilter Proxy Management", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _load_settings() -> GlobalSettings:
    if _SETTINGS_PATH.exists():
        return GlobalSettings.model_validate_json(_SETTINGS_PATH.read_text())
    return GlobalSettings()


# Paths reachable without a session (so the login page can load and submit).
_PUBLIC_PATHS = {"/login.html", "/api/login", "/api/logout", "/api/auth-status"}


@app.middleware("http")
async def require_auth(request: Request, call_next):
    s = _load_settings()
    # Auth only applies when enabled AND a password is set.
    if s.auth_enabled and s.password_hash:
        path = request.url.path
        if path not in _PUBLIC_PATHS:
            token = request.cookies.get(auth.COOKIE_NAME)
            if not auth.token_valid(token, s.password_hash, s.secret_key):
                if path.startswith("/api/"):
                    return JSONResponse({"detail": "authentication required"}, status_code=401)
                return RedirectResponse("/login.html")
    return await call_next(request)


@app.get("/api/auth-status")
def auth_status(request: Request):
    s = _load_settings()
    token = request.cookies.get(auth.COOKIE_NAME)
    return {
        "enabled": s.auth_enabled and bool(s.password_hash),
        "has_password": bool(s.password_hash),
        "authenticated": auth.token_valid(token, s.password_hash, s.secret_key),
    }


@app.post("/api/login")
def login(payload: dict = Body(...)):
    s = _load_settings()
    if not s.password_hash:
        return {"ok": True}  # no password configured
    if not auth.verify_password(payload.get("password", ""), s.password_hash):
        return JSONResponse({"ok": False, "detail": "Invalid password"}, status_code=401)
    resp = JSONResponse({"ok": True})
    resp.set_cookie(
        auth.COOKIE_NAME,
        auth.session_token(s.password_hash, s.secret_key),
        httponly=True, samesite="lax", max_age=7 * 24 * 3600,
    )
    return resp


@app.post("/api/logout")
def logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(auth.COOKIE_NAME)
    return resp


app.include_router(policies.router, prefix="/api/policies", tags=["policies"])
app.include_router(settings_router.router, prefix="/api/settings", tags=["settings"])


@app.get("/api/status")
def get_status():
    from shared.models import GlobalSettings
    cfg_path = Path(__file__).parent.parent.parent / "config" / "settings.json"
    settings = GlobalSettings()
    if cfg_path.exists():
        settings = GlobalSettings.model_validate_json(cfg_path.read_text())

    port = settings.primary_proxy_port
    proxy_running = _port_open("127.0.0.1", port) or _port_open("::1", port)

    root = Path(__file__).parent.parent.parent
    return {
        "proxy_running": proxy_running,
        "proxy_port": port,
        "proxy_listen": settings.proxy_listen,
        "mgmt_port": settings.mgmt_port,
        "recent_blocks": _tail_jsonl(root / settings.blocks_log_path.lstrip("./"), 50),
        "recent_requests": _tail_jsonl(root / settings.request_log_path.lstrip("./"), 100),
    }


def _tail_jsonl(path: Path, limit: int) -> list[dict]:
    """Return up to `limit` most-recent JSON records from a .jsonl file (newest first)."""
    out: list[dict] = []
    if not path.exists():
        return out
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return out
    for line in reversed(lines[-(limit * 4):]):
        try:
            out.append(json.loads(line))
        except Exception:
            pass
        if len(out) >= limit:
            break
    return out


@app.get("/api/ca-cert")
def download_ca_cert():
    from shared.models import GlobalSettings
    cfg_path = Path(__file__).parent.parent.parent / "config" / "settings.json"
    settings = GlobalSettings()
    if cfg_path.exists():
        settings = GlobalSettings.model_validate_json(cfg_path.read_text())

    root = Path(__file__).parent.parent.parent
    cert_dir = root / settings.cert_dir.lstrip("./")
    for name in ("mitmproxy-ca-cert.cer", "mitmproxy-ca-cert.pem", "mitmproxy-ca.pem"):
        cert_file = cert_dir / name
        if cert_file.exists():
            return FileResponse(cert_file, filename=name, media_type="application/x-pem-file")
    return {"error": "CA certificate not found. Run install script first."}


def _port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


# Serve management UI as static files — must be last
_ui_dir = Path(__file__).parent.parent / "ui"
if _ui_dir.exists():
    app.mount("/", StaticFiles(directory=str(_ui_dir), html=True), name="ui")
