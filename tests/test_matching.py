import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from proxy.matching import host_matches, url_matches, url_in_list, domain_in_list


class TestHostMatches:
    def test_exact_match(self):
        assert host_matches("example.com", "example.com")

    def test_exact_no_match(self):
        assert not host_matches("other.com", "example.com")

    def test_wildcard_subdomain(self):
        assert host_matches("sub.example.com", "*.example.com")

    def test_wildcard_apex(self):
        # *.example.com should also match example.com itself
        assert host_matches("example.com", "*.example.com")

    def test_wildcard_deep_subdomain(self):
        assert host_matches("a.b.example.com", "*.example.com")

    def test_wildcard_no_partial(self):
        # notexample.com should not match *.example.com
        assert not host_matches("notexample.com", "*.example.com")

    def test_glob_pattern(self):
        # fnmatch glob without leading *. prefix (that prefix is handled as subdomain wildcard)
        assert host_matches("foo.example.com", "foo.example.*")

    def test_empty_pattern(self):
        assert not host_matches("example.com", "")

    def test_whitespace_pattern(self):
        assert not host_matches("example.com", "   ")


class TestUrlMatches:
    def test_path_pattern_matches_url_schemeless(self):
        # scheme-less path pattern should match full URL
        assert url_matches("example.com", "https://example.com/path/to/page", "example.com/path")

    def test_path_pattern_matches_url_with_scheme(self):
        # full URL pattern also works
        assert url_matches("example.com", "https://example.com/path/to/page", "https://example.com/path")

    def test_path_glob_matches_url(self):
        assert url_matches("example.com", "https://example.com/page.html", "example.com/*.html")

    def test_path_pattern_no_match(self):
        assert not url_matches("example.com", "https://example.com/other", "example.com/path")

    def test_domain_pattern_matches_host(self):
        assert url_matches("example.com", "https://example.com/foo", "example.com")

    def test_wildcard_host_pattern(self):
        assert url_matches("sub.example.com", "https://sub.example.com/", "*.example.com")

    def test_empty_pattern(self):
        assert not url_matches("example.com", "https://example.com/", "")

    def test_no_match(self):
        assert not url_matches("other.com", "https://other.com/", "example.com")


class TestUrlInList:
    def test_matches_one_of_several(self):
        patterns = ["good.com", "bad.com", "example.com"]
        assert url_in_list("example.com", "https://example.com/", patterns)

    def test_no_match(self):
        assert not url_in_list("other.com", "https://other.com/", ["example.com", "bad.com"])

    def test_empty_list(self):
        assert not url_in_list("example.com", "https://example.com/", [])

    def test_url_path_pattern(self):
        # scheme-less path pattern matched against https:// URL
        assert url_in_list("example.com", "https://example.com/specific/path", ["example.com/specific/"])

    def test_skips_empty_patterns(self):
        assert not url_in_list("example.com", "https://example.com/", ["", "  "])


class TestDomainInList:
    def test_apex_match(self):
        assert domain_in_list("example.com", ["example.com"])

    def test_subdomain_match(self):
        assert domain_in_list("sub.example.com", ["example.com"])

    def test_deep_subdomain_match(self):
        assert domain_in_list("a.b.example.com", ["example.com"])

    def test_no_partial_label_match(self):
        assert not domain_in_list("notexample.com", ["example.com"])

    def test_leading_wildcard_dot_stripped(self):
        # *.example.com behaves the same as example.com for domain_in_list
        assert domain_in_list("sub.example.com", ["*.example.com"])
        assert domain_in_list("example.com", ["*.example.com"])

    def test_empty_list(self):
        assert not domain_in_list("example.com", [])

    def test_empty_pattern_skipped(self):
        assert not domain_in_list("example.com", [""])

    def test_multiple_patterns(self):
        assert domain_in_list("school.edu", ["example.com", "school.edu"])
        assert not domain_in_list("other.com", ["example.com", "school.edu"])


class TestImageTextShouldFilter:
    """Test _should_filter from image_classifier and text_classifier accept URL patterns."""

    def test_image_should_filter_exclude_domain(self):
        from proxy.addons.image_classifier import _should_filter
        from shared.models import ImageClassifierConfig
        cfg = ImageClassifierConfig(enabled=True, exclude=["art-museum.org"])
        assert not _should_filter("art-museum.org", "https://art-museum.org/image.jpg", cfg)
        assert _should_filter("other.com", "https://other.com/image.jpg", cfg)

    def test_image_should_filter_include_only_domain(self):
        from proxy.addons.image_classifier import _should_filter
        from shared.models import ImageClassifierConfig
        cfg = ImageClassifierConfig(enabled=True, include_only=["watch.me"])
        assert _should_filter("watch.me", "https://watch.me/img.png", cfg)
        assert not _should_filter("elsewhere.com", "https://elsewhere.com/img.png", cfg)

    def test_image_should_filter_exclude_url_path(self):
        from proxy.addons.image_classifier import _should_filter
        from shared.models import ImageClassifierConfig
        cfg = ImageClassifierConfig(enabled=True, exclude=["example.com/safe/"])
        # URL matching the exclude path should NOT be filtered
        assert not _should_filter("example.com", "https://example.com/safe/img.jpg", cfg)
        # URL not matching the exclude path should be filtered
        assert _should_filter("example.com", "https://example.com/unsafe/img.jpg", cfg)

    def test_image_should_filter_include_only_url_path(self):
        from proxy.addons.image_classifier import _should_filter
        from shared.models import ImageClassifierConfig
        cfg = ImageClassifierConfig(enabled=True, include_only=["example.com/filtered/"])
        assert _should_filter("example.com", "https://example.com/filtered/img.jpg", cfg)
        assert not _should_filter("example.com", "https://example.com/other/img.jpg", cfg)

    def test_text_should_filter_exclude_domain(self):
        from proxy.addons.text_classifier import _should_filter
        from shared.models import TextClassifierConfig
        cfg = TextClassifierConfig(enabled=True, exclude=["medical.edu"])
        assert not _should_filter("medical.edu", "https://medical.edu/page", cfg)
        assert _should_filter("other.com", "https://other.com/page", cfg)

    def test_text_should_filter_include_only_url_path(self):
        from proxy.addons.text_classifier import _should_filter
        from shared.models import TextClassifierConfig
        cfg = TextClassifierConfig(enabled=True, include_only=["example.com/adult/"])
        assert _should_filter("example.com", "https://example.com/adult/page", cfg)
        assert not _should_filter("example.com", "https://example.com/news/page", cfg)

    def test_no_restrictions_always_filter(self):
        from proxy.addons.image_classifier import _should_filter
        from shared.models import ImageClassifierConfig
        cfg = ImageClassifierConfig(enabled=True)
        assert _should_filter("anything.com", "https://anything.com/img.jpg", cfg)
