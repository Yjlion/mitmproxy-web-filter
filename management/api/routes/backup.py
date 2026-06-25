from __future__ import annotations
import io
import re
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import Response
from shared.models import GlobalSettings, Policy

router = APIRouter()
_PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
_SETTINGS_PATH = _PROJECT_ROOT / "config" / "settings.json"

# Only allow settings.json + policy files with safe names.
_VALID_ENTRY = re.compile(r"^(?:settings\.json|policies/[a-zA-Z0-9_\-]+\.json)$")

_MAX_BYTES = 50 * 1024 * 1024  # 50 MB — far larger than any real backup


def _load_settings() -> GlobalSettings:
    if _SETTINGS_PATH.exists():
        return GlobalSettings.model_validate_json(_SETTINGS_PATH.read_text(encoding="utf-8-sig"))
    return GlobalSettings()


def _policies_dir() -> Path:
    s = _load_settings()
    return _PROJECT_ROOT / s.policies_dir.lstrip("./")


@router.get("")
def export_backup():
    """Download a ZIP of all policies + settings for migration or disaster-recovery.

    The archive contains settings.json (including hashed credentials) and every
    policy/*.json.  The CA bundle is exported separately via /api/certs/export."""
    buf = io.BytesIO()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    pol_dir = _policies_dir()

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if _SETTINGS_PATH.exists():
            zf.write(str(_SETTINGS_PATH), "settings.json")
        if pol_dir.exists():
            for p in sorted(pol_dir.glob("*.json")):
                zf.write(str(p), f"policies/{p.name}")

    buf.seek(0)
    filename = f"webfilter-backup-{stamp}.zip"
    return Response(
        content=buf.read(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("")
async def import_backup(file: UploadFile = File(...)):
    """Restore policies and/or settings from a backup ZIP created by export_backup.

    Each entry is validated before anything is written; an invalid file aborts
    the whole import so the system is never left in a half-restored state."""
    raw = await file.read()
    if len(raw) > _MAX_BYTES:
        raise HTTPException(status_code=400, detail="File too large for a backup bundle.")

    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Not a valid ZIP file.")

    names = zf.namelist()

    bad = [n for n in names if not _VALID_ENTRY.match(n)]
    if bad:
        raise HTTPException(
            status_code=400,
            detail=f"Unexpected entries in backup: {bad[:5]}",
        )

    # Validate everything first so we don't partially write on error.
    parsed: list[tuple[str, str]] = []
    for name in names:
        try:
            data = zf.read(name).decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail=f"{name} is not valid UTF-8.")

        if name == "settings.json":
            try:
                GlobalSettings.model_validate_json(data)
            except Exception as exc:
                raise HTTPException(status_code=400, detail=f"Invalid settings.json: {exc}")
        else:
            try:
                Policy.model_validate_json(data)
            except Exception as exc:
                raise HTTPException(status_code=400, detail=f"Invalid policy {name}: {exc}")

        parsed.append((name, data))

    # All entries valid — write them out.
    pol_dir = _policies_dir()
    restored_policies: list[str] = []
    restored_settings = False

    for name, data in parsed:
        if name == "settings.json":
            _SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
            _SETTINGS_PATH.write_text(data, encoding="utf-8")
            restored_settings = True
        else:
            pol_dir.mkdir(parents=True, exist_ok=True)
            pol_name = Policy.model_validate_json(data).name
            (pol_dir / Path(name).name).write_text(data, encoding="utf-8")
            restored_policies.append(pol_name)

    return {
        "ok": True,
        "restored_settings": restored_settings,
        "restored_policies": restored_policies,
        "note": "Restart the proxy for settings changes to take full effect.",
    }
