"""
Per-module isolation tests.

Each filtering module is exercised with *only that module enabled* (every other
module disabled), so overlapping behavior can't mask or interfere with the one
under test. Each module is checked both ways: it acts when enabled, and is inert
when disabled.
"""
import sys
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from shared.models import Policy

MODULES = ["url_filter", "doh", "safesearch", "youtube", "text_classifier", "image_classifier"]


# --- fake mitmproxy flow ------------------------------------------------------

class FakeHeaders(dict):
    """Case-insensitive-enough header map (addons use lowercase keys)."""
    def get(self, k, default=""):
        return super().get(k.lower(), default)
    def __setitem__(self, k, v):
        super().__setitem__(k.lower(), v)
    def pop(self, k, default=None):
        return super().pop(k.lower(), default)


class FakeRequest:
    def __init__(self, url, method="GET"):
        from urllib.parse import urlparse
        self.url = url
        self.method = method
        p = urlparse(url)
        self.pretty_url = url
        self.pretty_host = p.hostname or ""
        self.path = (p.path or "/") + (("?" + p.query) if p.query else "")
        self.headers = FakeHeaders()


class FakeResponse:
    def __init__(self, status=200, headers=None, text="", raw=b""):
        self.status_code = status
        self.headers = FakeHeaders(headers or {})
        self.text = text
        self.raw_content = raw


class FakeConn:
    def __init__(self, ip="203.0.113.7"):
        self.peername = (ip, 12345)


class FakeFlow:
    def __init__(self, url, response=None, method="GET", client_ip="203.0.113.7"):
        self.request = FakeRequest(url, method)
        self.response = response
        self.client_conn = FakeConn(client_ip)
        self.metadata = {}


def only(module, **cfg) -> Policy:
    """A policy with exactly one module enabled (all others disabled by default)."""
    p = Policy(name=f"only-{module}")
    section = getattr(p, module)
    section.enabled = True
    for k, v in cfg.items():
        setattr(section, k, v)
    # Sanity: every other module must be off.
    for m in MODULES:
        if m != module:
            assert getattr(p, m).enabled is False
    return p


def is_block_page(resp) -> bool:
    if resp is None:
        return False
    body = getattr(resp, "content", b"") or b""
    return b"Access Blocked" in body


# --- url_filter ---------------------------------------------------------------

class TestUrlFilterIsolated:
    def test_blocks_listed_host(self):
        from proxy.addons.url_filter import UrlFilter
        flow = FakeFlow("http://bad.example.com/page")
        flow.metadata["policy"] = only("url_filter", block=["bad.example.com"])
        UrlFilter().request(flow)
        assert is_block_page(flow.response)
        assert flow.metadata["wf_action"] == "blocked"

    def test_allows_unlisted(self):
        from proxy.addons.url_filter import UrlFilter
        flow = FakeFlow("http://good.example.com/")
        flow.metadata["policy"] = only("url_filter", block=["bad.example.com"])
        UrlFilter().request(flow)
        assert flow.response is None

    def test_inert_when_disabled(self):
        from proxy.addons.url_filter import UrlFilter
        p = Policy(name="off")  # url_filter disabled
        flow = FakeFlow("http://bad.example.com/")
        flow.metadata["policy"] = p
        UrlFilter().request(flow)
        assert flow.response is None


# --- doh (network stubbed; detection logic covered in test_doh.py) ------------

class TestDohIsolated:
    @staticmethod
    def _run(monkeypatch, blocked, enabled=True):
        import asyncio
        from proxy.addons import doh_filter
        calls = {"n": 0}
        async def fake_query(host, server):
            calls["n"] += 1
            return blocked
        monkeypatch.setattr(doh_filter, "_query_doh", fake_query)
        flow = FakeFlow("http://tracker.example.com/")
        flow.metadata["policy"] = only("doh", server="https://dns.example/dns-query") if enabled else Policy(name="off")
        asyncio.run(doh_filter.DohFilter().request(flow))
        return flow, calls["n"]

    def test_blocks_when_resolver_says_blocked(self, monkeypatch):
        flow, _ = self._run(monkeypatch, True)
        assert is_block_page(flow.response)
        assert flow.metadata["wf_action"] == "blocked"

    def test_allows_when_resolver_ok(self, monkeypatch):
        flow, _ = self._run(monkeypatch, False)
        assert flow.response is None

    def test_inert_when_disabled(self, monkeypatch):
        flow, n = self._run(monkeypatch, True, enabled=False)
        assert flow.response is None
        assert n == 0  # never even queried


# --- safesearch ---------------------------------------------------------------

class TestSafeSearchIsolated:
    def test_injects_safe_param(self):
        from proxy.addons.safesearch import SafeSearch
        flow = FakeFlow("https://www.google.com/search?q=cats")
        flow.metadata["policy"] = only("safesearch")
        SafeSearch().request(flow)
        assert "safe=active" in flow.request.url
        assert flow.metadata.get("wf_action") == "modified"

    def test_blocks_image_tab(self):
        from proxy.addons.safesearch import SafeSearch
        flow = FakeFlow("https://www.bing.com/images/search?q=x")
        flow.metadata["policy"] = only("safesearch", block_images_tab=True)
        SafeSearch().request(flow)
        assert is_block_page(flow.response)

    def test_inert_when_disabled(self):
        from proxy.addons.safesearch import SafeSearch
        flow = FakeFlow("https://www.google.com/search?q=cats")
        flow.metadata["policy"] = Policy(name="off")
        SafeSearch().request(flow)
        assert "safe=active" not in flow.request.url
        assert flow.response is None


# --- youtube ------------------------------------------------------------------

def _player_body(channel="UC_x5XG1OV2P6uZZ5FSM9Ttw", author="Blocked Channel"):
    return json.dumps({
        "videoDetails": {"videoId": "v1", "channelId": channel, "author": author},
        "playabilityStatus": {"status": "OK"},
        "streamingData": {"formats": ["url"]},
    })


class TestYouTubeIsolated:
    def test_blocks_listed_channel(self):
        from proxy.addons.youtube_filter import YouTubeFilter
        flow = FakeFlow(
            "https://www.youtube.com/youtubei/v1/player",
            response=FakeResponse(headers={"content-type": "application/json"}, text=_player_body()),
            method="POST",
        )
        flow.metadata["policy"] = only("youtube", mode="blacklist", channels=["Blocked Channel"])
        YouTubeFilter().response(flow)
        out = json.loads(flow.response.text)
        assert out["playabilityStatus"]["status"] == "ERROR"
        assert "streamingData" not in out

    def test_allows_unlisted_channel(self):
        from proxy.addons.youtube_filter import YouTubeFilter
        flow = FakeFlow(
            "https://www.youtube.com/youtubei/v1/player",
            response=FakeResponse(headers={"content-type": "application/json"}, text=_player_body(author="Allowed")),
            method="POST",
        )
        flow.metadata["policy"] = only("youtube", mode="blacklist", channels=["Blocked Channel"])
        YouTubeFilter().response(flow)
        assert json.loads(flow.response.text)["playabilityStatus"]["status"] == "OK"

    def test_inert_when_disabled(self):
        from proxy.addons.youtube_filter import YouTubeFilter
        flow = FakeFlow(
            "https://www.youtube.com/youtubei/v1/player",
            response=FakeResponse(headers={"content-type": "application/json"}, text=_player_body()),
            method="POST",
        )
        flow.metadata["policy"] = Policy(name="off")
        YouTubeFilter().response(flow)
        assert json.loads(flow.response.text)["playabilityStatus"]["status"] == "OK"


# --- text_classifier (keyword path; no ML model needed) -----------------------

class TestTextClassifierIsolated:
    ADULT = ("This page is about porn and nude xxx hentai content. " * 4)
    CLEAN = ("A wholesome article about gardening, recipes and weather. " * 4)

    def test_blocks_adult_text(self):
        from proxy.addons.text_classifier import TextClassifier
        flow = FakeFlow("http://x.example.com/",
                        response=FakeResponse(headers={"content-type": "text/html"}, text=self.ADULT))
        flow.metadata["policy"] = only("text_classifier")
        TextClassifier().response(flow)
        assert is_block_page(flow.response)

    def test_allows_clean_text(self):
        from proxy.addons.text_classifier import TextClassifier
        flow = FakeFlow("http://x.example.com/",
                        response=FakeResponse(headers={"content-type": "text/html"}, text=self.CLEAN))
        flow.metadata["policy"] = only("text_classifier")
        TextClassifier().response(flow)
        assert not is_block_page(flow.response)

    def test_inert_when_disabled(self):
        from proxy.addons.text_classifier import TextClassifier
        flow = FakeFlow("http://x.example.com/",
                        response=FakeResponse(headers={"content-type": "text/html"}, text=self.ADULT))
        flow.metadata["policy"] = Policy(name="off")
        TextClassifier().response(flow)
        assert not is_block_page(flow.response)


# --- image_classifier (NudeNet stubbed; no model/network needed) --------------

class TestImageClassifierIsolated:
    def test_blocks_nsfw_image(self, monkeypatch):
        from proxy.addons import image_classifier
        monkeypatch.setattr(image_classifier, "_is_nsfw", lambda body, t: (True, []))
        flow = FakeFlow("http://x.example.com/p.jpg",
                        response=FakeResponse(headers={"content-type": "image/jpeg"}, raw=b"x" * 11000))
        flow.metadata["policy"] = only("image_classifier", action="block")
        image_classifier.ImageClassifier().response(flow)
        assert flow.response.raw_content == image_classifier._TRANSPARENT_GIF
        assert flow.metadata["wf_action"] == "modified"

    def test_checkerboard_action_replaces_with_png(self, monkeypatch):
        from proxy.addons import image_classifier as ic
        import io, os
        from PIL import Image
        monkeypatch.setattr(ic, "_is_nsfw", lambda body, t: (True, []))
        jpeg = io.BytesIO()
        # noise so the encoded JPEG exceeds the 10 KB classify threshold
        Image.frombytes("RGB", (300, 200), os.urandom(300 * 200 * 3)).save(jpeg, "JPEG", quality=95)
        flow = FakeFlow("http://x.example.com/p.jpg",
                        response=FakeResponse(headers={"content-type": "image/jpeg"}, raw=jpeg.getvalue()))
        flow.metadata["policy"] = only("image_classifier", action="checkerboard")
        ic.ImageClassifier().response(flow)
        out = Image.open(io.BytesIO(flow.response.raw_content))
        assert out.format == "PNG" and out.size == (300, 200)
        assert flow.response.headers.get("content-type") == "image/png"

    def test_allows_sfw_image(self, monkeypatch):
        from proxy.addons import image_classifier
        monkeypatch.setattr(image_classifier, "_is_nsfw", lambda body, t: (False, []))
        flow = FakeFlow("http://x.example.com/p.jpg",
                        response=FakeResponse(headers={"content-type": "image/jpeg"}, raw=b"x" * 11000))
        flow.metadata["policy"] = only("image_classifier", action="block")
        image_classifier.ImageClassifier().response(flow)
        assert flow.response.raw_content == b"x" * 11000

    def test_inert_when_disabled(self, monkeypatch):
        from proxy.addons import image_classifier
        calls = {"n": 0}
        monkeypatch.setattr(image_classifier, "_is_nsfw", lambda body, t: (calls.__setitem__("n", calls["n"] + 1), (True, []))[1])
        flow = FakeFlow("http://x.example.com/p.jpg",
                        response=FakeResponse(headers={"content-type": "image/jpeg"}, raw=b"x" * 11000))
        flow.metadata["policy"] = Policy(name="off")
        image_classifier.ImageClassifier().response(flow)
        assert flow.response.raw_content == b"x" * 11000
        assert calls["n"] == 0


# --- mitm_control -------------------------------------------------------------

class TestMitmControlIsolated:
    def test_include_mode_marks_passthrough(self):
        from proxy.addons.mitm_control import MitmControl
        p = Policy(name="m")
        p.mitm.mode = "include"
        p.mitm.sites = ["bank.com"]
        flow = FakeFlow("http://other.com/")
        flow.metadata["policy"] = p
        MitmControl().request(flow)
        assert flow.metadata.get("mitm_passthrough") is True

    def test_include_mode_listed_site_intercepted(self):
        from proxy.addons.mitm_control import MitmControl
        p = Policy(name="m")
        p.mitm.mode = "include"
        p.mitm.sites = ["bank.com"]
        flow = FakeFlow("http://bank.com/")
        flow.metadata["policy"] = p
        MitmControl().request(flow)
        assert "mitm_passthrough" not in flow.metadata

    def _ua_flow(self, ua: str) -> "FakeFlow":
        flow = FakeFlow("http://x.example.com/")
        flow.request.headers["user-agent"] = ua
        return flow

    def test_ua_exclude_matching_passes_through(self):
        from proxy.addons.mitm_control import MitmControl
        p = Policy(name="m")
        p.mitm.ua_mode = "exclude"
        p.mitm.user_agents = ["Spotify", "Roku"]
        flow = self._ua_flow("Spotify/8.9 (Windows)")
        flow.metadata["policy"] = p
        MitmControl().request(flow)
        assert flow.metadata.get("mitm_passthrough") is True

    def test_ua_exclude_nonmatching_filtered(self):
        from proxy.addons.mitm_control import MitmControl
        p = Policy(name="m")
        p.mitm.ua_mode = "exclude"
        p.mitm.user_agents = ["Spotify"]
        flow = self._ua_flow("Mozilla/5.0 (Windows NT 10.0) Chrome/120")
        flow.metadata["policy"] = p
        MitmControl().request(flow)
        assert "mitm_passthrough" not in flow.metadata

    def test_ua_include_only_matching_filtered(self):
        from proxy.addons.mitm_control import MitmControl
        p = Policy(name="m")
        p.mitm.ua_mode = "include"
        p.mitm.user_agents = ["Chrome"]
        # Listed UA → intercepted/filtered (no passthrough).
        listed = self._ua_flow("Mozilla/5.0 Chrome/120")
        listed.metadata["policy"] = p
        MitmControl().request(listed)
        assert "mitm_passthrough" not in listed.metadata
        # Unlisted UA → passes through.
        other = self._ua_flow("curl/8.4.0")
        other.metadata["policy"] = p
        MitmControl().request(other)
        assert other.metadata.get("mitm_passthrough") is True

    def test_ua_match_is_case_insensitive(self):
        from proxy.addons.mitm_control import MitmControl
        p = Policy(name="m")
        p.mitm.ua_mode = "exclude"
        p.mitm.user_agents = ["spotify"]
        flow = self._ua_flow("SPOTIFY/8.9")
        flow.metadata["policy"] = p
        MitmControl().request(flow)
        assert flow.metadata.get("mitm_passthrough") is True

    def test_ua_off_is_inert(self):
        from proxy.addons.mitm_control import MitmControl
        p = Policy(name="m")
        p.mitm.ua_mode = "off"
        p.mitm.user_agents = ["Spotify"]
        flow = self._ua_flow("Spotify/8.9")
        flow.metadata["policy"] = p
        MitmControl().request(flow)
        assert "mitm_passthrough" not in flow.metadata

    def test_ua_passthrough_skips_url_filter(self):
        """UA passthrough must short-circuit url_filter, which runs right after
        mitm_control — otherwise a bypassed client is still blocked by URL rules."""
        from proxy.addons.mitm_control import MitmControl
        from proxy.addons.url_filter import UrlFilter
        p = Policy(name="m")
        p.mitm.ua_mode = "exclude"
        p.mitm.user_agents = ["Spotify"]
        p.url_filter.enabled = True
        p.url_filter.block = ["x.example.com"]
        flow = self._ua_flow("Spotify/8.9")
        flow.metadata["policy"] = p
        MitmControl().request(flow)
        UrlFilter().request(flow)
        assert flow.response is None  # not blocked
