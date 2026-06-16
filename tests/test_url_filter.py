import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import proxy.addons.url_filter as url_filter
from proxy.addons.url_filter import _host_matches, _url_matches, UrlFilter
from shared.categories import CategoryStore
from shared.models import Policy


class TestHostMatches:
    def test_exact(self):
        assert _host_matches("evil.com", "evil.com")
        assert not _host_matches("other.com", "evil.com")

    def test_wildcard(self):
        assert _host_matches("sub.evil.com", "*.evil.com")
        assert _host_matches("evil.com", "*.evil.com")
        assert not _host_matches("notevil.com", "*.evil.com")

    def test_glob(self):
        assert _host_matches("evil.com", "ev?l.com")


class TestUrlMatches:
    def test_exact_domain(self):
        assert _url_matches("bad.com", "https://bad.com/page", "bad.com")
        assert not _url_matches("good.com", "https://good.com/page", "bad.com")

    def test_wildcard_domain(self):
        assert _url_matches("sub.bad.com", "https://sub.bad.com/", "*.bad.com")

    def test_url_prefix(self):
        assert _url_matches("example.com", "https://example.com/bad/path", "https://example.com/bad")

    def test_glob_url(self):
        assert _url_matches("example.com", "https://example.com/ads/banner.jpg", "https://example.com/ads/*")


def _flow(host, url):
    class Req:
        def __init__(s): s.pretty_host = host; s.pretty_url = url
    class Conn: peername = ("127.0.0.1", 1)
    class Flow:
        def __init__(s): s.request = Req(); s.client_conn = Conn(); s.metadata = {}; s.response = None
    return Flow()


class TestCategoryBlocking:
    @pytest.fixture(autouse=True)
    def _store(self, tmp_path, monkeypatch):
        d = tmp_path / "ads"; d.mkdir()
        (d / "domains").write_text("ad.net\n")
        monkeypatch.setattr(url_filter, "category_store", CategoryStore(base=tmp_path))

    def _policy(self, **uf):
        p = Policy(name="p")
        p.url_filter.enabled = True
        for k, v in uf.items():
            setattr(p.url_filter, k, v)
        return p

    def test_category_blocks(self):
        flow = _flow("track.ad.net", "https://track.ad.net/x")
        flow.metadata["policy"] = self._policy(categories=["ads"])
        UrlFilter().request(flow)
        assert flow.response is not None
        assert b"Access Blocked" in flow.response.content

    def test_allow_overrides_category(self):
        flow = _flow("track.ad.net", "https://track.ad.net/x")
        flow.metadata["policy"] = self._policy(categories=["ads"], allow=["track.ad.net"])
        UrlFilter().request(flow)
        assert flow.response is None
        assert flow.metadata.get("url_allowed") is True

    def test_unlisted_host_passes(self):
        flow = _flow("good.com", "https://good.com/")
        flow.metadata["policy"] = self._policy(categories=["ads"])
        UrlFilter().request(flow)
        assert flow.response is None

    def test_whitelist_allows_category_member(self):
        flow = _flow("track.ad.net", "https://track.ad.net/")
        flow.metadata["policy"] = self._policy(mode="whitelist", categories=["ads"])
        UrlFilter().request(flow)
        assert flow.response is None  # in an allowed category → permitted

    def test_whitelist_blocks_non_member(self):
        flow = _flow("other.com", "https://other.com/")
        flow.metadata["policy"] = self._policy(mode="whitelist", categories=["ads"])
        UrlFilter().request(flow)
        assert flow.response is not None
        assert b"Access Blocked" in flow.response.content

    def test_whitelist_allow_list_overrides(self):
        flow = _flow("other.com", "https://other.com/")
        flow.metadata["policy"] = self._policy(mode="whitelist", categories=["ads"], allow=["other.com"])
        UrlFilter().request(flow)
        assert flow.response is None
        assert flow.metadata.get("url_allowed") is True
