from __future__ import annotations
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from fastapi import APIRouter, Request
from shared.models import GlobalSettings, parse_listen

router = APIRouter()
_PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
_SETTINGS_PATH = _PROJECT_ROOT / "config" / "settings.json"


def build_wireguard_client_conf(server_key: str, client_key: str, host: str, port: int) -> str:
    """Reconstruct the WireGuard client config mitmproxy generates for its
    wireguard mode. server_key/client_key are base64 X25519 private keys from
    certs/wireguard.conf. Pure/testable; importing mitmproxy_rs happens here."""
    import mitmproxy_rs.wireguard as wg
    return (
        "[Interface]\n"
        f"PrivateKey = {client_key}\n"
        "Address = 10.0.0.1/32\n"
        "DNS = 10.0.0.53\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {wg.pubkey(server_key)}\n"
        "AllowedIPs = 0.0.0.0/0\n"
        f"Endpoint = {host}:{port}\n"
    )


def _load_settings() -> GlobalSettings:
    if _SETTINGS_PATH.exists():
        return GlobalSettings.model_validate_json(_SETTINGS_PATH.read_text(encoding="utf-8-sig"))
    return GlobalSettings()


def _wireguard_entry(s: GlobalSettings):
    """Return (host, port) of the first wireguard listen entry, or None."""
    for e in s.proxy_listen:
        mode, host, port = parse_listen(e)
        if mode == "wireguard":
            return host, (port or 51820)
    return None


@router.get("")
def get_wireguard(request: Request) -> dict:
    s = _load_settings()
    entry = _wireguard_entry(s)
    if entry is None:
        return {"enabled": False}

    listen_host, port = entry
    cert_dir = (_PROJECT_ROOT / s.cert_dir).resolve()
    conf_path = cert_dir / "wireguard.conf"

    try:
        import mitmproxy_rs.wireguard as wg
    except Exception as e:  # mitmproxy_rs unavailable in this env
        return {"enabled": True, "error": f"WireGuard support unavailable: {e}"}

    # Create the conf if the proxy hasn't yet; mitmproxy will reuse these keys.
    if not conf_path.exists():
        conf_path.parent.mkdir(parents=True, exist_ok=True)
        conf_path.write_text(json.dumps(
            {"server_key": wg.genkey(), "client_key": wg.genkey()}, indent=4
        ))
    try:
        c = json.loads(conf_path.read_text())
        server_key = c["server_key"]
        client_key = c["client_key"]
    except Exception as e:
        return {"enabled": True, "error": f"Invalid wireguard.conf: {e}"}

    # Endpoint host: prefer the configured listen host if concrete, else the
    # host the admin reached this UI on (PAC-style), else the request hostname.
    endpoint_host = listen_host
    if endpoint_host in ("", "0.0.0.0", "::", "[::]"):
        endpoint_host = (request.headers.get("host") or "").rsplit(":", 1)[0] or "127.0.0.1"

    conf = build_wireguard_client_conf(server_key, client_key, endpoint_host, port)
    return {
        "enabled": True,
        "conf": conf,
        "endpoint": f"{endpoint_host}:{port}",
        "server_pubkey": wg.pubkey(server_key),
    }
