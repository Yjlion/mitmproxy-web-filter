"""Tests for the config backup/restore API (GET/POST /api/backup)."""
import io
import json
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """TestClient with the management app wired to a temp directory."""
    import management.api.routes.backup as bk_mod
    import management.api.main as main_mod

    settings_path = tmp_path / "config" / "settings.json"
    settings_path.parent.mkdir(parents=True)

    policies_dir = tmp_path / "policies"
    policies_dir.mkdir()

    # Point the backup module at the temp dirs.
    monkeypatch.setattr(bk_mod, "_PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(bk_mod, "_SETTINGS_PATH", settings_path)
    monkeypatch.setattr(main_mod, "_ROOT", tmp_path)
    monkeypatch.setattr(main_mod, "_SETTINGS_PATH", settings_path)

    from management.api.main import app
    return TestClient(app), tmp_path, settings_path, policies_dir


def _make_zip(entries: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    buf.seek(0)
    return buf.read()


class TestExport:
    def test_returns_zip(self, client):
        tc, tmp_path, settings_path, policies_dir = client
        # Write a settings file and two policies so they appear in the export.
        settings_path.write_text('{"proxy_listen":["0.0.0.0:8080"]}', encoding="utf-8")
        (policies_dir / "kids.json").write_text('{"name":"kids","source_ips":[]}', encoding="utf-8")

        resp = tc.get("/api/backup")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/zip"

        zf = zipfile.ZipFile(io.BytesIO(resp.content))
        names = zf.namelist()
        assert "settings.json" in names
        assert "policies/kids.json" in names

    def test_empty_backup_when_no_files(self, client):
        tc, *_ = client
        resp = tc.get("/api/backup")
        assert resp.status_code == 200
        zf = zipfile.ZipFile(io.BytesIO(resp.content))
        assert zf.namelist() == []


class TestImport:
    def _valid_settings(self) -> str:
        return '{"proxy_listen":["0.0.0.0:8080"]}'

    def _valid_policy(self, name="test") -> str:
        return json.dumps({"name": name, "source_ips": []})

    def test_restores_settings_and_policies(self, client):
        tc, tmp_path, settings_path, policies_dir = client
        bundle = _make_zip({
            "settings.json": self._valid_settings(),
            "policies/test.json": self._valid_policy("test"),
        })

        resp = tc.post(
            "/api/backup",
            files={"file": ("backup.zip", bundle, "application/zip")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["restored_settings"] is True
        assert "test" in data["restored_policies"]

        assert settings_path.exists()
        assert (policies_dir / "test.json").exists()

    def test_restores_policies_only(self, client):
        tc, tmp_path, settings_path, policies_dir = client
        bundle = _make_zip({"policies/p.json": self._valid_policy("p")})

        resp = tc.post(
            "/api/backup",
            files={"file": ("backup.zip", bundle, "application/zip")},
        )
        assert resp.status_code == 200
        assert resp.json()["restored_settings"] is False
        assert (policies_dir / "p.json").exists()

    def test_rejects_bad_zip(self, client):
        tc, *_ = client
        resp = tc.post(
            "/api/backup",
            files={"file": ("x.zip", b"not a zip", "application/zip")},
        )
        assert resp.status_code == 400
        assert "ZIP" in resp.json()["detail"]

    def test_rejects_path_traversal(self, client):
        tc, *_ = client
        bundle = _make_zip({"../../etc/passwd": "root:x:0:0:..."})
        resp = tc.post(
            "/api/backup",
            files={"file": ("x.zip", bundle, "application/zip")},
        )
        assert resp.status_code == 400
        assert "Unexpected" in resp.json()["detail"]

    def test_rejects_invalid_policy_json(self, client):
        tc, *_ = client
        bundle = _make_zip({"policies/bad.json": '{"not":"a policy"}'})
        resp = tc.post(
            "/api/backup",
            files={"file": ("x.zip", bundle, "application/zip")},
        )
        assert resp.status_code == 400

    def test_rejects_invalid_settings_json(self, client):
        tc, *_ = client
        bundle = _make_zip({"settings.json": "not json at all"})
        resp = tc.post(
            "/api/backup",
            files={"file": ("x.zip", bundle, "application/zip")},
        )
        assert resp.status_code == 400

    def test_no_partial_write_on_error(self, client):
        """If a later entry is invalid, no files from this request should be written."""
        tc, tmp_path, settings_path, policies_dir = client
        # Put a valid policy first, then an invalid one — the valid one must not land.
        bundle = _make_zip({
            "policies/good.json": self._valid_policy("good"),
            "policies/bad.json": "{}",  # missing required 'name' field
        })
        resp = tc.post(
            "/api/backup",
            files={"file": ("x.zip", bundle, "application/zip")},
        )
        assert resp.status_code == 400
        assert not (policies_dir / "good.json").exists()
