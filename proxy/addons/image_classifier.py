"""
NSFW image classifier powered by NudeNet 3.x (ONNX, CPU, no GPU required).

NudeNet 3.x exposes detect(image_path) — a filesystem path, not bytes — so each
image is written to a short-lived temp file. The model ships with the package
(no network download). Images smaller than 10 KB are skipped (icons, favicons).
"""
from __future__ import annotations
import io
import os
import logging
import tempfile
from mitmproxy import http
from proxy.block_page import make_block_response
from proxy.matching import url_in_list

logger = logging.getLogger("webfilter.image")

# Cheap floor to discard genuine tracking pixels / spacers without decoding.
# Real filtering is gated on pixel dimensions (see _too_small), since heavily
# compressed thumbnails (e.g. Google image search) can be only a few KB.
_MIN_IMAGE_BYTES = 1_024  # 1 KB
# NudeNet 3.x class labels for explicit exposure (renamed from the 2.x labels).
_NSFW_LABELS = {
    "FEMALE_GENITALIA_EXPOSED",
    "MALE_GENITALIA_EXPOSED",
    "FEMALE_BREAST_EXPOSED",
    "BUTTOCKS_EXPOSED",
    "ANUS_EXPOSED",
}

_detector = None
_detector_attempted = False


def _get_detector():
    global _detector, _detector_attempted
    if _detector_attempted:
        return _detector
    _detector_attempted = True
    try:
        from nudenet import NudeDetector
        _detector = NudeDetector()
        logger.info("[image_classifier] NudeNet detector loaded")
    except Exception as e:
        logger.warning(f"[image_classifier] NudeNet not available: {e}")
    return _detector


def _is_nsfw(image_bytes: bytes, threshold: float) -> tuple[bool, list]:
    detector = _get_detector()
    if detector is None:
        return False, []
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as f:
            f.write(image_bytes)
            tmp_path = f.name
        detections = detector.detect(tmp_path)  # NudeNet 3.x takes a path
        hits = [
            d for d in detections
            if d.get("class") in _NSFW_LABELS and d.get("score", 0) >= threshold
        ]
        return bool(hits), hits
    except Exception as e:
        logger.debug(f"[image_classifier] Detection error: {e}")
        return False, []
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def _blur_image(image_bytes: bytes) -> bytes:
    """Heavily blur the ENTIRE image (radius scaled to its size)."""
    try:
        from PIL import Image, ImageFilter
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        radius = max(12, min(img.width, img.height) // 8)
        img = img.filter(ImageFilter.GaussianBlur(radius=radius))
        out = io.BytesIO()
        img.save(out, format="JPEG", quality=80)
        return out.getvalue()
    except Exception:
        return image_bytes


def _checkerboard(image_bytes: bytes) -> bytes:
    """Replace the image with a neutral checkerboard placeholder of the same size."""
    try:
        from PIL import Image, ImageDraw
        try:
            w, h = Image.open(io.BytesIO(image_bytes)).size
        except Exception:
            w, h = 320, 240
        light, dark = (245, 245, 240), (220, 220, 212)
        board = Image.new("RGB", (w, h), light)
        draw = ImageDraw.Draw(board)
        tile = max(8, min(w, h) // 10)
        for ty, y in enumerate(range(0, h, tile)):
            for tx, x in enumerate(range(0, w, tile)):
                if (tx + ty) % 2:
                    draw.rectangle([x, y, x + tile, y + tile], fill=dark)
        out = io.BytesIO()
        board.save(out, format="PNG")
        return out.getvalue()
    except Exception:
        return _TRANSPARENT_GIF


_TRANSPARENT_GIF = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!"
    b"\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
)


def _too_small(image_bytes: bytes, min_dimension: int) -> bool:
    """True if the image's largest side is under min_dimension pixels.

    Reads only the image header (no full decode). If dimensions can't be
    determined, returns False so the image still gets classified.
    """
    if min_dimension <= 0:
        return False
    try:
        from PIL import Image
        with Image.open(io.BytesIO(image_bytes)) as img:
            w, h = img.size
        return max(w, h) < min_dimension
    except Exception:
        return False


def _should_filter(host: str, url: str, cfg) -> bool:
    if cfg.include_only:
        return url_in_list(host, url, cfg.include_only)
    if cfg.exclude:
        return not url_in_list(host, url, cfg.exclude)
    return True


class ImageClassifier:
    def response(self, flow: http.HTTPFlow) -> None:
        if flow.metadata.get("url_allowed") or flow.metadata.get("mitm_passthrough"):
            return

        policy = flow.metadata.get("policy")
        if not policy or not policy.image_classifier.enabled:
            return

        if not flow.response:
            return

        ct = flow.response.headers.get("content-type", "")
        if not ct.startswith("image/"):
            return

        host = flow.request.pretty_host
        url = flow.request.pretty_url
        if not _should_filter(host, url, policy.image_classifier):
            return

        body = flow.response.raw_content
        if not body or len(body) < _MIN_IMAGE_BYTES:
            return

        cfg = policy.image_classifier
        if _too_small(body, cfg.min_dimension):
            return

        nsfw, detections = _is_nsfw(body, cfg.threshold)
        if not nsfw:
            return

        if cfg.action == "checkerboard":
            new_body, ctype = _checkerboard(body), "image/png"
        elif cfg.action == "block":
            new_body, ctype = _TRANSPARENT_GIF, "image/gif"
        else:  # blur the entire image
            new_body, ctype = _blur_image(body), "image/jpeg"

        flow.response.raw_content = new_body
        flow.response.headers["content-type"] = ctype
        flow.response.headers["content-length"] = str(len(new_body))

        flow.metadata["wf_action"] = "modified"
        flow.metadata["wf_component"] = "image_classifier"
