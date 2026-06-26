from __future__ import annotations
import csv
import io
import socket
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from fastapi import FastAPI, Request, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response

from management.api.routes import policies, settings as settings_router, certs
from management.api.routes import wireguard as wireguard_router
from management.api.routes import tools as tools_router
from management.api.routes import backup as backup_router
from management.api import auth, pac
from shared.models import GlobalSettings
from shared.version import get_version

_ROOT = Path(__file__).parent.parent.parent
_SETTINGS_PATH = _ROOT / "config" / "settings.json"

app = FastAPI(title="WebFilter Proxy Management", version=get_version())

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_EXPORT_ROWS = 500_000
_VALID_KINDS = {"requests", "blocks"}
_VALID_FORMATS = {"csv", "xlsx"}


def _load_settings() -> GlobalSettings:
    if _SETTINGS_PATH.exists():
        return GlobalSettings.model_validate_json(_SETTINGS_PATH.read_text(encoding="utf-8-sig"))
    return GlobalSettings()


def _ensure_logstore_configured(settings: GlobalSettings) -> None:
    """Configure the logstore for read-only schema access (management side).
    The proxy owns migration; here we only ensure the schema exists so reads
    work even before the proxy has started."""
    from shared import logstore
    logstore.configure(
        settings.db_path,
        settings.log_retention_days,
        log_requests=settings.log_requests,
        log_blocks=settings.log_blocks,
    )


# Paths reachable without a session (so the login page can load and submit, and
# so unauthenticated devices can fetch the proxy auto-config file).
_PUBLIC_PATHS = {
    "/login.html", "/api/login", "/api/logout", "/api/auth-status",
    "/api/version", "/proxy.pac", "/wpad.dat", "/wpad.da",
}


@app.get("/api/version")
def get_app_version():
    return {"version": get_version()}


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
app.include_router(certs.router, prefix="/api/certs", tags=["certs"])
app.include_router(backup_router.router, prefix="/api/backup", tags=["backup"])
app.include_router(wireguard_router.router, prefix="/api/wireguard", tags=["wireguard"])
app.include_router(tools_router.router, prefix="/api/tools", tags=["tools"])


@app.get("/api/status")
def get_status():
    from shared import logstore

    settings = _load_settings()
    _ensure_logstore_configured(settings)

    port = settings.primary_proxy_port
    proxy_running = _port_open("127.0.0.1", port) or _port_open("::1", port)

    return {
        "proxy_running": proxy_running,
        "proxy_port": port,
        "proxy_listen": settings.proxy_listen,
        "mgmt_port": settings.mgmt_port,
        "recent_blocks": logstore.tail("blocks", 50),
        "recent_requests": logstore.tail("requests", 100),
    }


@app.get("/api/categories")
def get_categories():
    """Shared site categories available to policies (from categories/index.json)."""
    from shared.categories import list_categories, index_meta, configure
    s = _load_settings()
    configure(s.categories_dir)
    return {"categories": list_categories(), **index_meta()}


@app.get("/api/logs")
def get_logs(kind: str = "blocks", limit: int = 500):
    """Tail of the log store. kind = 'blocks' | 'requests'."""
    from shared import logstore

    if kind not in _VALID_KINDS:
        return JSONResponse({"detail": f"kind must be one of {list(_VALID_KINDS)}"}, status_code=400)
    settings = _load_settings()
    _ensure_logstore_configured(settings)
    limit = max(1, min(limit, 5000))
    return {"kind": kind, "entries": logstore.tail(kind, limit)}


@app.get("/api/analytics")
def get_analytics(hours: int = 24):
    """Aggregate analytics from the SQLite log store over the last N hours."""
    from shared import logstore

    settings = _load_settings()
    _ensure_logstore_configured(settings)
    hours = max(1, min(hours, 720))
    cutoff = time.time() - hours * 3600
    return logstore.analytics(cutoff, window_hours=hours)


@app.get("/api/logs/export")
def export_logs(
    kind: str = "requests",
    format: str = "csv",
    start: int | None = None,
    end: int | None = None,
):
    """Stream a CSV or XLSX of either log within an optional time range."""
    from shared import logstore
    from shared.logstore import REQUEST_COLUMNS, BLOCK_COLUMNS

    # Validate inputs against whitelists — never interpolate table names from
    # user input directly.
    if kind not in _VALID_KINDS:
        return JSONResponse(
            {"detail": f"kind must be one of {list(_VALID_KINDS)}"},
            status_code=400,
        )
    if format not in _VALID_FORMATS:
        return JSONResponse(
            {"detail": f"format must be one of {list(_VALID_FORMATS)}"},
            status_code=400,
        )

    start_ts = start if start is not None else 0
    end_ts = end if end is not None else int(time.time())

    settings = _load_settings()
    _ensure_logstore_configured(settings)

    rows = logstore.rows_in_range(kind, start_ts, end_ts)

    if len(rows) > MAX_EXPORT_ROWS:
        return JSONResponse(
            {
                "detail": (
                    f"Export would return {len(rows):,} rows which exceeds the "
                    f"{MAX_EXPORT_ROWS:,}-row limit. Narrow the date range."
                )
            },
            status_code=400,
        )

    columns = REQUEST_COLUMNS if kind == "requests" else BLOCK_COLUMNS
    stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    filename_base = f"{kind}-{stamp}"

    if format == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
        return Response(
            content=buf.getvalue(),
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="{filename_base}.csv"'
            },
        )

    # XLSX
    import openpyxl
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = kind
    ws.append(list(columns))
    for row in rows:
        ws.append([row.get(c) for c in columns])

    buf_bytes = io.BytesIO()
    wb.save(buf_bytes)
    buf_bytes.seek(0)
    return Response(
        content=buf_bytes.read(),
        media_type=(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        ),
        headers={
            "Content-Disposition": f'attachment; filename="{filename_base}.xlsx"'
        },
    )


@app.get("/api/ca-cert")
def download_ca_cert():
    from shared.models import GlobalSettings
    cfg_path = Path(__file__).parent.parent.parent / "config" / "settings.json"
    settings = GlobalSettings()
    if cfg_path.exists():
        settings = GlobalSettings.model_validate_json(cfg_path.read_text(encoding="utf-8-sig"))

    root = Path(__file__).parent.parent.parent
    cert_dir = root / settings.cert_dir
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


def _pac_proxy_host(request: Request, settings: GlobalSettings) -> str:
    """Address to advertise in the PAC: the configured override, else the host
    the client used to reach this management server (so the PAC self-adapts)."""
    configured = (settings.pac_proxy_host or "").strip()
    if configured:
        return configured
    host = (request.url.hostname or request.client.host if request.client else "") or "127.0.0.1"
    # IPv6 literals must be bracketed in a PROXY directive.
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return host


def _serve_pac(request: Request) -> Response:
    settings = _load_settings()
    body = pac.render_pac(
        _pac_proxy_host(request, settings),
        settings.primary_proxy_port,
        settings.pac_direct_hosts,
        settings.pac_direct_ips,
    )
    return Response(content=body, media_type="application/x-ns-proxy-autoconfig")


@app.get("/proxy.pac")
def proxy_pac(request: Request) -> Response:
    return _serve_pac(request)


@app.get("/wpad.dat")
def wpad_dat(request: Request) -> Response:
    return _serve_pac(request)


@app.get("/wpad.da")
def wpad_da(request: Request) -> Response:
    return _serve_pac(request)


# Serve management UI as static files — must be last
_ui_dir = Path(__file__).parent.parent / "ui"
if _ui_dir.exists():
    app.mount("/", StaticFiles(directory=str(_ui_dir), html=True), name="ui")
