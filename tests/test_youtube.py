import sys
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from proxy.addons.youtube_filter import (
    _channel_listed, _is_blocked, _json_unescape, _norm_name,
    _CHANNEL_ID_RE, _AUTHOR_RE, _HANDLE_RE,
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
