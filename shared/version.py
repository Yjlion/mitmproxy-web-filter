from __future__ import annotations
import os
import subprocess
from functools import lru_cache
from pathlib import Path

# Repo/app root (shared/ sits directly under it, in both source checkouts and
# the shipped archive where this file lives at <appdir>/shared/version.py).
_ROOT = Path(__file__).resolve().parent.parent


@lru_cache(maxsize=1)
def get_version() -> str:
    """Resolve the app version, reflecting the GitHub release.

    Priority:
      1. The ``WEBFILTER_VERSION`` environment variable. The container image
         bakes the release tag here at build time (see Dockerfile ``ARG``),
         since the image ships without a ``VERSION`` file or ``.git`` directory.
      2. A ``VERSION`` file at the app root. CI writes the release tag here when
         building the archive (which ships without a ``.git`` directory), e.g.
         ``v0.2.0``.
      3. ``git describe --tags`` for a source checkout, e.g.
         ``v0.2.0-1-g29e6551`` (latest release tag plus commits ahead).
      4. ``"dev"`` when none is available.
    """
    env = os.environ.get("WEBFILTER_VERSION", "").strip()
    if env:
        return env
    vfile = _ROOT / "VERSION"
    if vfile.exists():
        v = vfile.read_text(encoding="utf-8").strip()
        if v:
            return v
    try:
        out = subprocess.run(
            ["git", "describe", "--tags", "--always"],
            cwd=_ROOT, capture_output=True, text=True, timeout=2,
        )
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except Exception:
        pass
    return "dev"
