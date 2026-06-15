from __future__ import annotations
import json
import time
from pathlib import Path
from mitmproxy import http
from jinja2 import Environment, FileSystemLoader

_template_dir = Path(__file__).parent
_env = Environment(loader=FileSystemLoader(str(_template_dir)), autoescape=True)

_blocks_log: Path | None = None


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

    template = _env.get_template("block_template.html")
    html = template.render(
        domain=flow.request.pretty_host,
        url=flow.request.pretty_url,
        reason=reason,
        component=component,
        policy_name=policy_name,
        custom_message=custom_message,
    )
    return http.Response.make(
        200,
        html.encode("utf-8"),
        {"Content-Type": "text/html; charset=utf-8"},
    )
