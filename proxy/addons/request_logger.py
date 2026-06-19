"""
Logs every request to the rolling request log. Registered last so it observes
the final action set by upstream filters (blocked / modified / ok).
"""
from __future__ import annotations
import time
from mitmproxy import http
from shared.logstore import log_request


class RequestLogger:
    def response(self, flow: http.HTTPFlow) -> None:
        status = flow.response.status_code if flow.response else 0
        self._record(flow, status)

    def error(self, flow: http.HTTPFlow) -> None:
        # Connection/upstream errors never reach the response hook.
        if "wf_logged" not in flow.metadata:
            self._record(flow, 0)

    def _record(self, flow: http.HTTPFlow, status: int) -> None:
        flow.metadata["wf_logged"] = True
        policy = flow.metadata.get("policy")
        log_request({
            "ts": int(time.time()),
            "method": flow.request.method,
            "host": flow.request.pretty_host,
            "path": flow.request.path[:200],
            "status": status,
            "action": flow.metadata.get("wf_action", "ok"),
            "component": flow.metadata.get("wf_component", ""),
            "policy": policy.name if policy else "",
            "client_ip": flow.client_conn.peername[0] if flow.client_conn.peername else "",
        })
