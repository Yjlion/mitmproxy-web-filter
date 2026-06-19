import sys
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared.categories import CategoryStore, _host_in_set, configure, list_categories, index_meta


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


class TestConfigure:
    def test_configure_redirects_list_categories(self, tmp_path):
        # Write a fake index.json into tmp_path
        cats = [{"name": "testcat", "count": 5, "updated": "2025-01-01T00:00:00Z"}]
        index = {"source": "test", "updated": "2025-01-01T00:00:00Z", "categories": cats}
        (tmp_path / "index.json").write_text(json.dumps(index), encoding="utf-8")

        configure(tmp_path)
        result = list_categories()
        assert len(result) == 1
        assert result[0]["name"] == "testcat"

    def test_configure_redirects_index_meta(self, tmp_path):
        index = {"source": "https://example.com/list.tar.gz", "updated": "2025-01-01T00:00:00Z", "categories": []}
        (tmp_path / "index.json").write_text(json.dumps(index), encoding="utf-8")

        configure(tmp_path)
        meta = index_meta()
        assert meta.get("source") == "https://example.com/list.tar.gz"

    def test_configure_missing_index_returns_empty(self, tmp_path):
        configure(tmp_path / "nonexistent")
        assert list_categories() == []


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
