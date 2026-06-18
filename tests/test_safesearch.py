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


class TestPerEngineConfig:
    def test_legacy_global_flags_migrate_to_all_engines(self):
        from shared.models import SafeSearchConfig, SAFESEARCH_ENGINES
        cfg = SafeSearchConfig.model_validate(
            {"enabled": True, "block_images_tab": True, "block_ai_tab": True}
        )
        assert set(cfg.engines) == set(SAFESEARCH_ENGINES)
        for name in SAFESEARCH_ENGINES:
            assert cfg.engines[name].block_images_tab is True
            assert cfg.engines[name].block_videos_tab is False
            assert cfg.engines[name].block_ai_tab is True
        # The legacy fields are dropped from the upgraded model.
        assert not hasattr(cfg, "block_images_tab")

    def test_explicit_engines_not_overwritten_by_legacy(self):
        from shared.models import SafeSearchConfig
        cfg = SafeSearchConfig.model_validate(
            {
                "enabled": True,
                "block_videos_tab": True,  # legacy, should be ignored
                "engines": {"google": {"block_images_tab": True}},
            }
        )
        assert set(cfg.engines) == {"google"}
        assert cfg.engines["google"].block_images_tab is True
        assert cfg.engines["google"].block_videos_tab is False

    def test_no_tab_flags_leaves_engines_empty(self):
        from shared.models import SafeSearchConfig
        cfg = SafeSearchConfig.model_validate({"enabled": True})
        assert cfg.engines == {}


class TestPerEngineBlocking:
    def _flow(self, url):
        from urllib.parse import urlparse

        class _Req:
            def __init__(self, url):
                p = urlparse(url)
                self.url = url
                self.pretty_url = url
                self.pretty_host = p.hostname or ""

        class _Flow:
            def __init__(self, url):
                self.request = _Req(url)
                self.response = None
                self.metadata = {}

        return _Flow(url)

    def _policy(self, engines):
        from shared.models import Policy, SafeSearchEngineConfig
        p = Policy(name="t")
        p.safesearch.enabled = True
        p.safesearch.engines = {
            k: SafeSearchEngineConfig(**v) for k, v in engines.items()
        }
        return p

    def test_blocks_only_configured_engine(self):
        from proxy.addons.safesearch import SafeSearch
        # Google image tab blocked, Bing left alone.
        pol = self._policy({"google": {"block_images_tab": True}})

        g = self._flow("https://www.google.com/search?q=x&tbm=isch")
        g.metadata["policy"] = pol
        SafeSearch().request(g)
        assert g.response is not None  # blocked

        b = self._flow("https://www.bing.com/images/search?q=x")
        b.metadata["policy"] = pol
        SafeSearch().request(b)
        assert b.response is None  # not configured → not blocked

    def test_blocks_ai_assistant_host(self):
        from proxy.addons.safesearch import SafeSearch
        pol = self._policy({"bing": {"block_ai_tab": True}})
        f = self._flow("https://copilot.microsoft.com/")
        f.metadata["policy"] = pol
        SafeSearch().request(f)
        assert f.response is not None


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
