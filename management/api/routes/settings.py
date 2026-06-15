from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from fastapi import APIRouter, Body, HTTPException
from shared.models import GlobalSettings
from management.api import auth

router = APIRouter()
_PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
_SETTINGS_PATH = _PROJECT_ROOT / "config" / "settings.json"

# Secret fields never sent to the browser.
_SECRET_FIELDS = ("password_hash", "secret_key")


def _load() -> GlobalSettings:
    if _SETTINGS_PATH.exists():
        return GlobalSettings.model_validate_json(_SETTINGS_PATH.read_text())
    return GlobalSettings()


def _save(s: GlobalSettings) -> None:
    _SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    _SETTINGS_PATH.write_text(s.model_dump_json(indent=2))


def _sanitized(s: GlobalSettings) -> dict:
    d = s.model_dump()
    for f in _SECRET_FIELDS:
        d.pop(f, None)
    d["has_password"] = bool(s.password_hash)
    return d


@router.get("")
def get_settings() -> dict:
    return _sanitized(_load())


@router.put("")
def update_settings(payload: dict = Body(...)) -> dict:
    current = _load()
    new_password = payload.pop("new_password", None)
    # Never trust client-supplied secrets / derived fields.
    for f in (*_SECRET_FIELDS, "has_password"):
        payload.pop(f, None)

    data = current.model_dump()
    data.update(payload)
    s = GlobalSettings.model_validate(data)
    # Preserve server-managed secrets across updates.
    s.password_hash = current.password_hash
    s.secret_key = current.secret_key

    if new_password:
        s.password_hash = auth.hash_password(new_password)
        if not s.secret_key:
            s.secret_key = auth.new_secret()

    if s.auth_enabled and not s.password_hash:
        raise HTTPException(status_code=400, detail="Set a password before enabling authentication.")

    _save(s)
    return _sanitized(s)
