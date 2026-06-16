import sys
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from proxy.addons.youtube_filter import (
    _channel_listed, _is_blocked, _json_unescape, _norm_name,
    _CHANNEL_ID_RE, _AUTHOR_RE, _HANDLE_RE,
    _is_channel_path, _is_home_path,
    _strip_comments_from_next, _strip_sidebar_from_next, _browse_channel_identity,
)
from shared.models import YouTubeConfig

CID = "UC_x5XG1OV2P6uZZ5FSM9Ttw"  # 24 chars


class TestChannelListed:
    def test_by_id(self):
        assert _channel_listed(CID, "Google Developers", "@googledevelopers", [CID])

    def test_by_name_case_insensitive(self):
        assert _channel_listed(CID, "Google Developers", None, ["google developers"])

    def test_by_handle_with_at(self):
        assert _channel_listed(CID, "Google Developers", "@GoogleDevelopers", ["@googledevelopers"])

    def test_by_handle_without_at(self):
        assert _channel_listed(CID, None, "@MrBeast", ["MrBeast"])

    def test_no_match(self):
        assert not _channel_listed(CID, "Google Developers", "@gd", ["UCotherchannelxxxxxxxxxx", "SomeoneElse"])

    def test_empty_entries_ignored(self):
        assert not _channel_listed(CID, "Name", None, ["", "  "])


class TestIsBlocked:
    def test_blacklist_match(self):
        cfg = YouTubeConfig(enabled=True, mode="blacklist", channels=["@MrBeast"])
        assert _is_blocked(CID, "MrBeast", "@MrBeast", cfg)

    def test_blacklist_no_match(self):
        cfg = YouTubeConfig(enabled=True, mode="blacklist", channels=["@MrBeast"])
        assert not _is_blocked(CID, "Khan Academy", "@khanacademy", cfg)

    def test_whitelist_allows_listed(self):
        cfg = YouTubeConfig(enabled=True, mode="whitelist", channels=["Khan Academy"])
        assert not _is_blocked(CID, "Khan Academy", None, cfg)

    def test_whitelist_blocks_unlisted(self):
        cfg = YouTubeConfig(enabled=True, mode="whitelist", channels=["Khan Academy"])
        assert _is_blocked(CID, "Random Channel", None, cfg)


class TestJsonUnescape:
    def test_unicode_amp(self):
        assert _json_unescape("Tom \\u0026 Jerry") == "Tom & Jerry"

    def test_plain(self):
        assert _json_unescape("Plain Name") == "Plain Name"


class TestHtmlExtraction:
    def test_extract_from_html(self):
        html = (
            'var x = {"author":"Cool \\u0026 Channel","channelId":"' + CID + '",'
            '"canonicalBaseUrl":"/@coolchannel"};'
        )
        assert _CHANNEL_ID_RE.search(html).group(1) == CID
        assert _json_unescape(_AUTHOR_RE.search(html).group(1)) == "Cool & Channel"
        assert _HANDLE_RE.search(html).group(1) == "@coolchannel"


class TestPlayerRewrite:
    """Verify the player-API handler marks a blocked video unplayable."""

    def _make_flow(self, player_json):
        # Minimal stand-in for an mitmproxy flow/response.
        class Resp:
            def __init__(self, text):
                self.text = text
                self.headers = {"content-type": "application/json"}
        class Req:
            path = "/youtubei/v1/player"
            pretty_host = "www.youtube.com"
            pretty_url = "https://www.youtube.com/youtubei/v1/player"
        class Conn:
            peername = ("127.0.0.1", 1234)
        class Flow:
            def __init__(self, text):
                self.response = Resp(text)
                self.request = Req()
                self.client_conn = Conn()
                self.metadata = {}
        return Flow(player_json)

    def test_blocked_video_becomes_error(self):
        from proxy.addons.youtube_filter import YouTubeFilter
        from shared.models import Policy
        policy = Policy(name="kids")
        policy.youtube.enabled = True
        policy.youtube.mode = "blacklist"
        policy.youtube.channels = ["@MrBeast"]

        body = json.dumps({
            "videoDetails": {"videoId": "abc", "channelId": CID, "author": "MrBeast"},
            "microformat": {"playerMicroformatRenderer": {"ownerProfileUrl": "http://www.youtube.com/@MrBeast"}},
            "playabilityStatus": {"status": "OK"},
            "streamingData": {"formats": ["stream-url"]},
        })
        flow = self._make_flow(body)
        YouTubeFilter()._handle_player(flow, policy)

        out = json.loads(flow.response.text)
        assert out["playabilityStatus"]["status"] == "ERROR"
        assert "streamingData" not in out

    def test_allowed_video_untouched(self):
        from proxy.addons.youtube_filter import YouTubeFilter
        from shared.models import Policy
        policy = Policy(name="kids")
        policy.youtube.enabled = True
        policy.youtube.mode = "blacklist"
        policy.youtube.channels = ["@MrBeast"]

        body = json.dumps({
            "videoDetails": {"videoId": "abc", "channelId": CID, "author": "Khan Academy"},
            "playabilityStatus": {"status": "OK"},
            "streamingData": {"formats": ["stream-url"]},
        })
        flow = self._make_flow(body)
        YouTubeFilter()._handle_player(flow, policy)

        out = json.loads(flow.response.text)
        assert out["playabilityStatus"]["status"] == "OK"
        assert "streamingData" in out


class TestPathClassifiers:
    @pytest.mark.parametrize("path", [
        "/@MrBeast", "/@Mr.Beast", "/channel/" + CID, "/c/SomeName", "/user/SomeName",
        "/@MrBeast/videos",
    ])
    def test_channel_paths(self, path):
        assert _is_channel_path(path)

    @pytest.mark.parametrize("path", ["/watch", "/watch?v=x", "/results", "/", "/feed/subscriptions"])
    def test_non_channel_paths(self, path):
        assert not _is_channel_path(path)

    def test_home_paths(self):
        assert _is_home_path("/")
        assert _is_home_path("/feed/subscriptions")
        assert not _is_home_path("/watch")


class TestNextTransforms:
    def _watch_next(self):
        return {
            "contents": {"twoColumnWatchNextResults": {
                "results": {"results": {"contents": [
                    {"itemSectionRenderer": {"sectionIdentifier": "video-info"}},
                    {"itemSectionRenderer": {"sectionIdentifier": "comment-item-section"}},
                ]}},
                "secondaryResults": {"secondaryResults": {"results": ["related1", "related2"]}},
            }}
        }

    def test_strip_comments(self):
        data = self._watch_next()
        assert _strip_comments_from_next(data) is True
        kept = data["contents"]["twoColumnWatchNextResults"]["results"]["results"]["contents"]
        ids = [i["itemSectionRenderer"]["sectionIdentifier"] for i in kept]
        assert "comment-item-section" not in ids
        assert "video-info" in ids

    def test_strip_comments_idempotent(self):
        data = {"contents": {"twoColumnWatchNextResults": {"results": {"results": {"contents": []}}}}}
        assert _strip_comments_from_next(data) is False

    def test_strip_sidebar(self):
        data = self._watch_next()
        assert _strip_sidebar_from_next(data) is True
        assert "secondaryResults" not in data["contents"]["twoColumnWatchNextResults"]

    def test_strip_sidebar_absent(self):
        data = {"contents": {"twoColumnWatchNextResults": {}}}
        assert _strip_sidebar_from_next(data) is False


class TestBrowseIdentity:
    def test_channel_metadata_extracted(self):
        data = {"metadata": {"channelMetadataRenderer": {
            "title": "FDD",
            "externalId": CID,
            "vanityChannelUrl": "http://www.youtube.com/@FDD",
        }}}
        cid, title, handle = _browse_channel_identity(data)
        assert cid == CID and title == "FDD" and handle == "@FDD"

    def test_feed_has_no_identity(self):
        cid, title, handle = _browse_channel_identity({"contents": {}})
        assert cid is None and title is None and handle is None


def _flow(path, body, ct="application/json"):
    """A minimal mitmproxy-flow stand-in routed through YouTubeFilter.response."""
    class Resp:
        def __init__(self, text, ct):
            self.text = text
            self._ct = ct
            self.headers = {"content-type": ct}
            self.status_code = 200
        @property
        def content(self):
            return self.text.encode() if isinstance(self.text, str) else self.text
    class Req:
        def __init__(self, path):
            self.path = path
            self.pretty_host = "www.youtube.com"
            self.pretty_url = "https://www.youtube.com" + path
    class Conn:
        peername = ("127.0.0.1", 1234)
    class Flow:
        def __init__(self):
            self.response = Resp(body, ct)
            self.request = Req(path)
            self.client_conn = Conn()
            self.metadata = {}
    return Flow()


def _policy(**yt):
    from shared.models import Policy
    p = Policy(name="kids")
    p.youtube.enabled = True
    for k, v in yt.items():
        setattr(p.youtube, k, v)
    return p


class TestResponseDispatch:
    def _run(self, flow, policy):
        from proxy.addons.youtube_filter import YouTubeFilter
        flow.metadata["policy"] = policy
        YouTubeFilter().response(flow)

    def test_channel_page_blocked_by_handle(self):
        flow = _flow("/@FDD", "<html>channel</html>", ct="text/html; charset=utf-8")
        self._run(flow, _policy(mode="blacklist", channels=["@FDD"]))
        assert b"Access Blocked" in flow.response.content

    def test_channel_page_allowed_when_not_listed(self):
        flow = _flow("/@SomethingElse", "<html>channel</html>", ct="text/html; charset=utf-8")
        self._run(flow, _policy(mode="blacklist", channels=["@FDD"]))
        assert flow.response.content == b"<html>channel</html>"

    def test_home_blocked_in_whitelist(self):
        flow = _flow("/", "<html>home</html>", ct="text/html; charset=utf-8")
        self._run(flow, _policy(mode="whitelist", channels=["Khan Academy"]))
        assert b"Access Blocked" in flow.response.content

    def test_home_allowed_in_blacklist(self):
        flow = _flow("/", "<html>home</html>", ct="text/html; charset=utf-8")
        self._run(flow, _policy(mode="blacklist", channels=["@FDD"]))
        assert flow.response.content == b"<html>home</html>"

    def test_home_not_blocked_when_block_home_off(self):
        flow = _flow("/", "<html>home</html>", ct="text/html; charset=utf-8")
        self._run(flow, _policy(mode="whitelist", channels=["x"], block_home=False))
        assert flow.response.content == b"<html>home</html>"

    def test_browse_channel_page_blocked(self):
        body = json.dumps({"responseContext": {}, "metadata": {"channelMetadataRenderer": {
            "title": "FDD", "externalId": CID, "vanityChannelUrl": "http://www.youtube.com/@FDD"}}})
        flow = _flow("/youtubei/v1/browse", body)
        self._run(flow, _policy(mode="blacklist", channels=["FDD"]))
        out = json.loads(flow.response.text)
        assert "metadata" not in out  # contents stripped

    def test_get_watch_blocks_video_and_keeps_array_shape(self):
        # Mirrors the real /get_watch body: [ {playerResponse}, {watchNextResponse} ]
        body = json.dumps([
            {"playerResponse": {
                "videoDetails": {"channelId": CID, "author": "FDD"},
                "microformat": {"playerMicroformatRenderer": {"ownerProfileUrl": "http://www.youtube.com/@FDD"}},
                "playabilityStatus": {"status": "OK"},
                "streamingData": {"formats": ["url"]}},
             "responseType": "player"},
            {"watchNextResponse": {"contents": {"twoColumnWatchNextResults": {
                "results": {"results": {"contents": [
                    {"itemSectionRenderer": {"sectionIdentifier": "comment-item-section"}}]}},
                "secondaryResults": {"x": 1}}}},
             "responseType": "watchNext"},
        ])
        flow = _flow("/youtubei/v1/get_watch", body)
        self._run(flow, _policy(mode="blacklist", channels=["FDD"],
                                remove_comments=True, remove_recommendations=True))
        out = json.loads(flow.response.text)
        assert isinstance(out, list) and len(out) == 2
        pr = out[0]["playerResponse"]
        assert pr["playabilityStatus"]["status"] == "ERROR"
        assert "streamingData" not in pr
        twocol = out[1]["watchNextResponse"]["contents"]["twoColumnWatchNextResults"]
        assert "secondaryResults" not in twocol
        assert twocol["results"]["results"]["contents"] == []

    def test_get_watch_allowed_video_untouched(self):
        body = json.dumps([
            {"playerResponse": {
                "videoDetails": {"channelId": CID, "author": "Khan Academy"},
                "playabilityStatus": {"status": "OK"},
                "streamingData": {"formats": ["url"]}}},
        ])
        flow = _flow("/youtubei/v1/get_watch", body)
        self._run(flow, _policy(mode="blacklist", channels=["FDD"]))
        out = json.loads(flow.response.text)
        assert out[0]["playerResponse"]["playabilityStatus"]["status"] == "OK"
        assert "streamingData" in out[0]["playerResponse"]

    def test_next_removes_comments_and_sidebar(self):
        body = json.dumps({"contents": {"twoColumnWatchNextResults": {
            "results": {"results": {"contents": [
                {"itemSectionRenderer": {"sectionIdentifier": "comment-item-section"}}]}},
            "secondaryResults": {"x": 1}}}})
        flow = _flow("/youtubei/v1/next", body)
        self._run(flow, _policy(remove_comments=True, remove_recommendations=True))
        out = json.loads(flow.response.text)
        twocol = out["contents"]["twoColumnWatchNextResults"]
        assert "secondaryResults" not in twocol
        assert twocol["results"]["results"]["contents"] == []
