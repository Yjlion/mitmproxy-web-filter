from __future__ import annotations
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from fastapi import APIRouter, HTTPException
from shared.models import Policy, GlobalSettings

router = APIRouter()
_PROJECT_ROOT = Path(__file__).parent.parent.parent.parent


def _policies_dir() -> Path:
    cfg_path = _PROJECT_ROOT / "config" / "settings.json"
    settings = GlobalSettings()
    if cfg_path.exists():
        settings = GlobalSettings.model_validate_json(cfg_path.read_text(encoding="utf-8-sig"))
    d = _PROJECT_ROOT / settings.policies_dir.lstrip("./")
    d.mkdir(parents=True, exist_ok=True)
    return d


def _safe_name(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_\-]", "_", name)


def _policy_path(name: str) -> Path:
    return _policies_dir() / f"{_safe_name(name)}.json"


@router.get("")
def list_policies() -> list[Policy]:
    policies = []
    for f in sorted(_policies_dir().glob("*.json")):
        try:
            policies.append(Policy.model_validate_json(f.read_text(encoding="utf-8-sig")))
        except Exception:
            pass
    return policies


@router.post("", status_code=201)
def create_policy(policy: Policy) -> Policy:
    path = _policy_path(policy.name)
    if path.exists():
        raise HTTPException(status_code=409, detail=f"Policy '{policy.name}' already exists")
    path.write_text(policy.model_dump_json(indent=2))
    return policy


@router.get("/{name}")
def get_policy(name: str) -> Policy:
    path = _policy_path(name)
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Policy '{name}' not found")
    return Policy.model_validate_json(path.read_text(encoding="utf-8-sig"))


@router.put("/{name}")
def update_policy(name: str, policy: Policy) -> Policy:
    path = _policy_path(name)
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Policy '{name}' not found")
    # If name changed, rename file
    if policy.name != name:
        new_path = _policy_path(policy.name)
        if new_path.exists():
            raise HTTPException(status_code=409, detail=f"Policy '{policy.name}' already exists")
        path.unlink()
        path = new_path
    path.write_text(policy.model_dump_json(indent=2))
    return policy


@router.delete("/{name}", status_code=204)
def delete_policy(name: str) -> None:
    path = _policy_path(name)
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Policy '{name}' not found")
    path.unlink()
