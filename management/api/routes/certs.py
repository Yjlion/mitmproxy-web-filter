from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import FileResponse
from shared.models import GlobalSettings

router = APIRouter()
_PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
_SETTINGS_PATH = _PROJECT_ROOT / "config" / "settings.json"

# The PEM mitmproxy uses as its CA — it holds BOTH the certificate and the
# private key. Copy this to another instance and it issues identical leaf
# certs, so client devices only ever need to trust one CA.
_CA_BUNDLE = "mitmproxy-ca.pem"
# Formats mitmproxy regenerates from the bundle on the next startup.
_DERIVED = (
    "mitmproxy-ca-cert.pem",
    "mitmproxy-ca-cert.cer",
    "mitmproxy-ca-cert.p12",
    "mitmproxy-ca.p12",
)


def _cert_dir() -> Path:
    s = GlobalSettings()
    if _SETTINGS_PATH.exists():
        s = GlobalSettings.model_validate_json(_SETTINGS_PATH.read_text(encoding="utf-8-sig"))
    return _PROJECT_ROOT / s.cert_dir


@router.get("/export")
def export_ca():
    """Download the full CA bundle (certificate + private key) so this proxy's
    identity can be copied to another instance."""
    path = _cert_dir() / _CA_BUNDLE
    if not path.exists():
        raise HTTPException(status_code=404, detail="CA bundle not found. Start the proxy once to generate it.")
    return FileResponse(path, filename=_CA_BUNDLE, media_type="application/x-pem-file")


@router.post("/import")
async def import_ca(file: UploadFile = File(...)):
    """Replace this instance's CA with an uploaded bundle (cert + key PEM, i.e.
    mitmproxy-ca.pem). The proxy must be restarted for the new CA to take effect."""
    raw = await file.read()
    if len(raw) > 256 * 1024:
        raise HTTPException(status_code=400, detail="File too large to be a CA bundle.")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="Not a PEM file (must be text).")
    if "PRIVATE KEY" not in text or "CERTIFICATE" not in text:
        raise HTTPException(
            status_code=400,
            detail="PEM must contain both a CERTIFICATE and a PRIVATE KEY (upload mitmproxy-ca.pem).",
        )

    cert_dir = _cert_dir()
    cert_dir.mkdir(parents=True, exist_ok=True)
    (cert_dir / _CA_BUNDLE).write_text(text, encoding="utf-8")
    # Drop the derived formats so mitmproxy regenerates them from the new bundle.
    removed = []
    for name in _DERIVED:
        p = cert_dir / name
        if p.exists():
            try:
                p.unlink()
                removed.append(name)
            except OSError:
                pass
    return {
        "ok": True,
        "imported": _CA_BUNDLE,
        "regenerated": removed,
        "note": "Restart the proxy for the new CA to take effect.",
    }
