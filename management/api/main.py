from __future__ import annotations
import json
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from fastapi import FastAPI, Request, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response

from management.api.routes import policies, settings as settings_router, certs
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


def _load_settings() -> GlobalSettings:
    if _SETTINGS_PATH.exists():
        return GlobalSettings.model_validate_json(_SETTINGS_PATH.read_text(encoding="utf-8-sig"))
    return GlobalSettings()


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


@app.get("/api/status")
def get_status():
    from shared.models import GlobalSettings
    cfg_path = Path(__file__).parent.parent.parent / "config" / "settings.json"
    settings = GlobalSettings()
    if cfg_path.exists():
        settings = GlobalSettings.model_validate_json(cfg_path.read_text(encoding="utf-8-sig"))

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


def _read_all_jsonl(path: Path) -> list[dict]:
    """Return all valid JSON records from a .jsonl file (oldest first)."""
    if not path.exists():
        return []
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return []
    out = []
    for line in lines:
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    return out


@app.get("/api/categories")
def get_categories():
    """Shared site categories available to policies (from categories/index.json)."""
    from shared.categories import list_categories, index_meta
    return {"categories": list_categories(), **index_meta()}


@app.get("/api/logs")
def get_logs(kind: str = "blocks", limit: int = 500):
    """Tail of a log file. kind = 'blocks' | 'requests'."""
    settings = _load_settings()
    root = Path(__file__).parent.parent.parent
    limit = max(1, min(limit, 5000))
    rel = settings.request_log_path if kind == "requests" else settings.blocks_log_path
    return {"kind": kind, "entries": _tail_jsonl(root / rel.lstrip("./"), limit)}


@app.get("/api/analytics")
def get_analytics(hours: int = 24):
    """Aggregate analytics from request and block logs over the last N hours."""
    import time
    from collections import Counter

    settings = _load_settings()
    root = Path(__file__).parent.parent.parent
    hours = max(1, min(hours, 720))
    cutoff = time.time() - hours * 3600

    requests = _read_all_jsonl(root / settings.request_log_path.lstrip("./"))
    blocks = _read_all_jsonl(root / settings.blocks_log_path.lstrip("./"))

    requests = [r for r in requests if r.get("ts", 0) >= cutoff]
    blocks = [b for b in blocks if b.get("ts", 0) >= cutoff]

    top_domains = Counter(b.get("domain", "") for b in blocks if b.get("domain"))
    blocks_by_component = Counter(b.get("component", "unknown") for b in blocks)
    request_actions = Counter(r.get("action", "unknown") for r in requests)

    per_device: dict[str, dict] = {}
    for r in requests:
        ip = r.get("client_ip") or "unknown"
        s = per_device.setdefault(ip, {"ip": ip, "total": 0, "blocked": 0, "policy": r.get("policy", "")})
        s["total"] += 1
        if r.get("action") == "blocked":
            s["blocked"] += 1

    # Hourly block buckets (label = hour boundary as unix timestamp)
    import math
    bucket_size = 3600
    blocks_over_time: dict[int, int] = {}
    for b in blocks:
        ts = b.get("ts", 0)
        bucket = int(math.floor(ts / bucket_size)) * bucket_size
        blocks_over_time[bucket] = blocks_over_time.get(bucket, 0) + 1
    blocks_timeline = [{"ts": k, "count": v} for k, v in sorted(blocks_over_time.items())]

    return {
        "window_hours": hours,
        "total_requests": len(requests),
        "total_blocks": len(blocks),
        "request_actions": dict(request_actions),
        "top_blocked_domains": [{"domain": d, "count": c} for d, c in top_domains.most_common(15)],
        "blocks_by_component": [{"component": k, "count": v} for k, v in blocks_by_component.most_common()],
        "per_device": sorted(per_device.values(), key=lambda x: -x["total"]),
        "blocks_timeline": blocks_timeline,
    }


@app.get("/api/ca-cert")
def download_ca_cert():
    from shared.models import GlobalSettings
    cfg_path = Path(__file__).parent.parent.parent / "config" / "settings.json"
    settings = GlobalSettings()
    if cfg_path.exists():
        settings = GlobalSettings.model_validate_json(cfg_path.read_text(encoding="utf-8-sig"))

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
