from __future__ import annotations
import json
import time
from pathlib import Path
from mitmproxy import http
from jinja2 import Environment, FileSystemLoader

_template_dir = Path(__file__).parent
_env = Environment(loader=FileSystemLoader(str(_template_dir)), autoescape=True)

_blocks_log: Path | None = None

# Project root → config/settings.json (holds the shared ui_language).
_SETTINGS_PATH = Path(__file__).parent.parent / "config" / "settings.json"

# RTL languages get dir="rtl" on the block page.
_RTL = {"he", "yi"}

# Block-page chrome, translated. The dynamic reason/component text is produced
# by the addons (English); only the static labels are localized here. Any
# missing language falls back to English per-key.
_BP_I18N = {
    "en": {"title": "Access Blocked", "reason": "Reason:", "filter": "Filter:", "policy": "Policy:"},
    "he": {"title": "הגישה נחסמה", "reason": "סיבה:", "filter": "מסנן:", "policy": "מדיניות:"},
    "yi": {"title": "צוטריט געשפּאַרט", "reason": "סיבה:", "filter": "פֿילטער:", "policy": "פּאָליסי:"},
    "es": {"title": "Acceso bloqueado", "reason": "Motivo:", "filter": "Filtro:", "policy": "Política:"},
    "fr": {"title": "Accès bloqué", "reason": "Motif :", "filter": "Filtre :", "policy": "Politique :"},
    "de": {"title": "Zugriff blockiert", "reason": "Grund:", "filter": "Filter:", "policy": "Richtlinie:"},
    "zh": {"title": "访问已被拦截", "reason": "原因：", "filter": "过滤器：", "policy": "策略："},
}


def _ui_language() -> str:
    """Read the shared interface language from settings.json (default 'en').
    Re-read per block so a language change in the UI takes effect immediately."""
    try:
        data = json.loads(_SETTINGS_PATH.read_text(encoding="utf-8-sig"))
        lang = data.get("ui_language", "en")
        return lang if lang in _BP_I18N else "en"
    except (OSError, ValueError):
        return "en"


def _bp_labels(lang: str) -> dict:
    base = _BP_I18N["en"]
    table = _BP_I18N.get(lang, base)
    return {k: table.get(k, base[k]) for k in base}


def init_logging(path: str) -> None:
    global _blocks_log
    _blocks_log = Path(path)
    _blocks_log.parent.mkdir(parents=True, exist_ok=True)


def log_block(
    flow: http.HTTPFlow,
    reason: str,
    component: str,
    policy=None,
) -> None:
    """Append a block event to the block log. Used both by the HTML block page
    and by components that block without returning the HTML page (e.g. the
    YouTube player API, which gets a JSON response instead)."""
    # Mark the flow so the request logger records this as a block (independent
    # of whether the blocks-log file is enabled).
    flow.metadata["wf_action"] = "blocked"
    flow.metadata["wf_component"] = component

    if not _blocks_log:
        return
    policy_name = policy.name if policy else "unknown"
    entry = {
        "ts": int(time.time()),
        "domain": flow.request.pretty_host,
        "url": flow.request.pretty_url,
        "reason": reason,
        "component": component,
        "policy": policy_name,
        "client_ip": flow.client_conn.peername[0] if flow.client_conn.peername else "",
    }
    try:
        with _blocks_log.open("a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass


def make_block_response(
    flow: http.HTTPFlow,
    reason: str,
    component: str,
    policy=None,
) -> http.Response:
    policy_name = policy.name if policy else "unknown"
    custom_message = policy.block_page.message if policy else ""

    log_block(flow, reason, component, policy)

    lang = _ui_language()
    template = _env.get_template("block_template.html")
    html = template.render(
        domain=flow.request.pretty_host,
        url=flow.request.pretty_url,
        reason=reason,
        component=component,
        policy_name=policy_name,
        custom_message=custom_message,
        lang=lang,
        dir="rtl" if lang in _RTL else "ltr",
        labels=_bp_labels(lang),
    )
    return http.Response.make(
        200,
        html.encode("utf-8"),
        {"Content-Type": "text/html; charset=utf-8"},
    )
