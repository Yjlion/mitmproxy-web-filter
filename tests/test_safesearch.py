import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from proxy.addons.safesearch import _inject_param, _match_engine


class TestInjectParam:
    def test_new_param(self):
        url = "https://www.google.com/search?q=test"
        result = _inject_param(url, "safe", "active")
        assert "safe=active" in result
        assert "q=test" in result

    def test_replaces_existing(self):
        url = "https://www.google.com/search?q=test&safe=off"
        result = _inject_param(url, "safe", "active")
        assert "safe=active" in result
        assert "safe=off" not in result


class TestMatchEngine:
    def test_google(self):
        engine = _match_engine("www.google.com")
        assert engine is not None
        assert engine["name"] == "google"

    def test_google_country(self):
        engine = _match_engine("www.google.co.uk")
        assert engine is not None
        assert engine["name"] == "google"

    def test_bing(self):
        engine = _match_engine("www.bing.com")
        assert engine["name"] == "bing"

    def test_duckduckgo(self):
        engine = _match_engine("duckduckgo.com")
        assert engine["name"] == "duckduckgo"

    def test_unknown(self):
        assert _match_engine("example.com") is None


class TestPolicyRoutingIp:
    def test_cidr_match(self):
        from proxy.addons.policy_router import get_policy
        from shared.models import Policy
        import proxy.addons.policy_router as pr
        p = Policy(name="test", source_ips=["10.0.0.0/8"])
        pr._policies = [p]
        assert get_policy("10.1.2.3") is p
        assert get_policy("192.168.1.1") is None

    def test_exact_ip(self):
        from proxy.addons.policy_router import get_policy
        from shared.models import Policy
        import proxy.addons.policy_router as pr
        p = Policy(name="test", source_ips=["192.168.1.50"])
        pr._policies = [p]
        assert get_policy("192.168.1.50") is p
        assert get_policy("192.168.1.51") is None

    def test_catch_all(self):
        from proxy.addons.policy_router import get_policy
        from shared.models import Policy
        import proxy.addons.policy_router as pr
        p = Policy(name="default", source_ips=[])
        pr._policies = [p]
        assert get_policy("10.0.0.1") is p
