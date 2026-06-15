import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from proxy.addons.url_filter import _host_matches, _url_matches


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
