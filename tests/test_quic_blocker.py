import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from unittest.mock import MagicMock
from proxy.addons.quic_blocker import QuicBlocker
from shared.models import Policy, UrlFilterConfig


def _flow(headers=None, policy=None, url_allowed=False, mitm_passthrough=False):
    flow = MagicMock()
    flow.metadata = {
        "url_allowed": url_allowed,
        "mitm_passthrough": mitm_passthrough,
        "policy": policy,
    }
    flow.response = MagicMock()
    flow.response.headers = dict(headers or {})
    return flow


def _policy(block_quic=True):
    p = Policy(name="test")
    p.url_filter = UrlFilterConfig(enabled=True, block_quic=block_quic)
    return p


class TestQuicBlocker:
    def setup_method(self):
        self.addon = QuicBlocker()

    def test_strips_alt_svc_when_block_quic_enabled(self):
        flow = _flow(
            headers={"alt-svc": 'h3=":443"; ma=2592000', "content-type": "text/html"},
            policy=_policy(block_quic=True),
        )
        self.addon.response(flow)
        assert "alt-svc" not in flow.response.headers
        assert "content-type" in flow.response.headers  # other headers untouched

    def test_preserves_alt_svc_when_block_quic_disabled(self):
        flow = _flow(
            headers={"alt-svc": 'h3=":443"'},
            policy=_policy(block_quic=False),
        )
        self.addon.response(flow)
        assert "alt-svc" in flow.response.headers

    def test_no_effect_when_alt_svc_absent(self):
        flow = _flow(headers={"content-type": "text/html"}, policy=_policy(block_quic=True))
        self.addon.response(flow)  # should not raise
        assert "alt-svc" not in flow.response.headers

    def test_skipped_when_url_allowed(self):
        flow = _flow(
            headers={"alt-svc": 'h3=":443"'},
            policy=_policy(block_quic=True),
            url_allowed=True,
        )
        self.addon.response(flow)
        assert "alt-svc" in flow.response.headers

    def test_skipped_when_mitm_passthrough(self):
        flow = _flow(
            headers={"alt-svc": 'h3=":443"'},
            policy=_policy(block_quic=True),
            mitm_passthrough=True,
        )
        self.addon.response(flow)
        assert "alt-svc" in flow.response.headers

    def test_skipped_when_no_policy(self):
        flow = _flow(headers={"alt-svc": 'h3=":443"'}, policy=None)
        self.addon.response(flow)
        assert "alt-svc" in flow.response.headers

    def test_skipped_when_response_is_none(self):
        flow = _flow(policy=_policy(block_quic=True))
        flow.response = None
        self.addon.response(flow)  # should not raise
