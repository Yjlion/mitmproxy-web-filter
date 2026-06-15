"""
Adult text classifier.

Uses a two-stage approach:
  1. Fast keyword pre-filter (always active, zero dependencies)
  2. Optional ML classifier (scikit-learn, loaded if available)

The ML model is expected at models/text_classifier.joblib.
Train it offline with scripts/train_text_classifier.py and include in the zip.
"""
from __future__ import annotations
import re
from pathlib import Path
import logging
from mitmproxy import http
from proxy.block_page import make_block_response

logger = logging.getLogger("webfilter.text")

_PROJECT_ROOT = Path(__file__).parent.parent.parent
_MODEL_PATH = _PROJECT_ROOT / "models" / "text_classifier.joblib"

_ml_classifier = None  # lazy-loaded
_ml_attempted = False


def _load_ml_model():
    global _ml_classifier, _ml_attempted
    if _ml_attempted:
        return
    _ml_attempted = True
    if not _MODEL_PATH.exists():
        return
    try:
        import joblib
        _ml_classifier = joblib.load(_MODEL_PATH)
        logger.info("[text_classifier] ML model loaded")
    except Exception as e:
        logger.warning(f"[text_classifier] ML model load failed: {e}")


# Keyword-based pre-filter (conservative, high-precision terms)
_ADULT_KEYWORDS = re.compile(
    r"\b(porn|pornography|xxx|hentai|nude|naked|erotic|masturbat|orgasm|"
    r"penis|vagina|anal sex|oral sex|blowjob|handjob|gangbang|threesome|"
    r"escort service|cam girl|onlyfans|nsfw|adult content)\b",
    re.IGNORECASE,
)
_MIN_KEYWORD_HITS = 3  # require multiple hits to reduce false positives


def _keyword_score(text: str) -> float:
    hits = len(_ADULT_KEYWORDS.findall(text))
    return min(hits / _MIN_KEYWORD_HITS, 1.0)


def _classify(text: str, threshold: float) -> bool:
    score = _keyword_score(text)
    if score >= 1.0:
        return True
    if _ml_classifier is not None:
        try:
            proba = _ml_classifier.predict_proba([text])[0][1]
            return proba >= threshold
        except Exception:
            pass
    return False


def _should_filter(host: str, cfg) -> bool:
    if cfg.include_only:
        return any(host == s or host.endswith("." + s) for s in cfg.include_only)
    if cfg.exclude:
        return not any(host == s or host.endswith("." + s) for s in cfg.exclude)
    return True


def _strip_html(html: str) -> str:
    try:
        from bs4 import BeautifulSoup
        return BeautifulSoup(html, "html.parser").get_text(separator=" ", strip=True)
    except ImportError:
        return re.sub(r"<[^>]+>", " ", html)


class TextClassifier:
    def response(self, flow: http.HTTPFlow) -> None:
        if flow.metadata.get("url_allowed") or flow.metadata.get("mitm_passthrough"):
            return

        policy = flow.metadata.get("policy")
        if not policy or not policy.text_classifier.enabled:
            return

        if not flow.response:
            return

        ct = flow.response.headers.get("content-type", "")
        if "text/html" not in ct:
            return

        host = flow.request.pretty_host
        if not _should_filter(host, policy.text_classifier):
            return

        _load_ml_model()

        try:
            html = flow.response.text
        except Exception:
            return

        text = _strip_html(html)
        if len(text) < 100:  # skip tiny pages
            return

        cfg = policy.text_classifier
        if _classify(text, cfg.threshold):
            flow.response = make_block_response(
                flow, "Adult text content detected", "text_classifier", policy
            )
