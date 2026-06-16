import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared.categories import CategoryStore, _host_in_set


def _make_store(tmp_path, name, domains):
    d = tmp_path / name
    d.mkdir(parents=True)
    (d / "domains").write_text("# header comment\n\n" + "\n".join(domains) + "\n")
    return CategoryStore(base=tmp_path)


class TestHostInSet:
    def test_exact(self):
        assert _host_in_set("bad.com", frozenset({"bad.com"}))

    def test_subdomain(self):
        assert _host_in_set("a.b.bad.com", frozenset({"bad.com"}))

    def test_no_partial_label_match(self):
        # "notbad.com" must not match "bad.com"
        assert not _host_in_set("notbad.com", frozenset({"bad.com"}))

    def test_stops_before_tld(self):
        assert not _host_in_set("example.com", frozenset({"com"}))


class TestCategoryStore:
    def test_loads_and_strips_comments(self, tmp_path):
        store = _make_store(tmp_path, "porn", ["EVIL.com", "two.com"])
        s = store.domains("porn")
        assert "evil.com" in s and "two.com" in s   # lowercased
        assert len(s) == 2                            # comment + blank dropped

    def test_match_any(self, tmp_path):
        store = _make_store(tmp_path, "ads", ["ad.net"])
        assert store.match_any("track.ad.net", ["ads"]) == "ads"
        assert store.match_any("track.ad.net", ["porn"]) is None

    def test_missing_category_is_empty(self, tmp_path):
        store = CategoryStore(base=tmp_path)
        assert store.domains("nope") == frozenset()
        assert store.match_any("x.com", ["nope"]) is None
