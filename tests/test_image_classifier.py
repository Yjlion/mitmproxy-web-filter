"""
Image classifier tests using the REAL NudeNet detector (skipped if unavailable).

We can't ship explicit imagery, so the real-model test verifies the end-to-end
wiring on a benign image (model loads, temp-file + detect() API works, benign =
allowed). The blocking/blur transforms are covered with a stubbed detector in
test_modules_isolated.py.
"""
import io
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

pytest.importorskip("nudenet")
pytest.importorskip("PIL")

from PIL import Image
from proxy.addons import image_classifier as ic


def _benign_jpeg(size=(320, 320), color=(120, 150, 180)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, "JPEG")
    return buf.getvalue()


def test_detector_loads():
    assert ic._get_detector() is not None


def test_benign_image_not_flagged():
    nsfw, hits = ic._is_nsfw(_benign_jpeg(), threshold=0.5)
    assert nsfw is False
    assert hits == []


def test_blur_image_produces_valid_jpeg():
    out = ic._blur_image(_benign_jpeg())
    Image.open(io.BytesIO(out)).verify()  # still decodable


def test_checkerboard_matches_dimensions():
    src = _benign_jpeg(size=(300, 200))
    out = ic._checkerboard(src)
    board = Image.open(io.BytesIO(out))
    assert board.size == (300, 200)  # layout-preserving placeholder
    assert board.format == "PNG"


def test_no_tempfile_leak(tmp_path, monkeypatch):
    before = set(Path(tempfile_dir()).glob("*.img"))
    ic._is_nsfw(_benign_jpeg(), threshold=0.5)
    after = set(Path(tempfile_dir()).glob("*.img"))
    assert before == after  # temp file cleaned up


def tempfile_dir():
    import tempfile
    return tempfile.gettempdir()
