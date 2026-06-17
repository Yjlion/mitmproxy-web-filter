from __future__ import annotations
from pathlib import Path
from typing import Literal
from pydantic import BaseModel, Field, field_validator, model_validator


def split_hostport(entry: str) -> tuple[str, int]:
    """Parse 'host:port' into (host, port). Accepts IPv4 (0.0.0.0:8080),
    bracketed IPv6 ([::1]:8080), and bare IPv6 (::1:8080 — port after last colon)."""
    entry = entry.strip()
    if entry.startswith("["):
        host, _, rest = entry[1:].partition("]")
        port = rest.lstrip(":")
    else:
        host, _, port = entry.rpartition(":")
        if not host:  # no colon present
            host, port = entry, ""
    return host, (int(port) if port.isdigit() else 0)


def to_mitm_mode(entry: str) -> str:
    """Convert a 'host:port' listen entry to a mitmproxy mode spec.
    mitmproxy 12 wants IPv6 hosts WITHOUT brackets (it splits on the last colon)."""
    host, port = split_hostport(entry)
    return f"regular@{host}:{port}"


class DohConfig(BaseModel):
    enabled: bool = False
    server: str = "https://1.1.1.3/dns-query"
    exclude: list[str] = Field(default_factory=list)
    include_only: list[str] = Field(default_factory=list)

    @field_validator("server")
    @classmethod
    def _clean_server(cls, v: str) -> str:
        # Trim stray whitespace (a common copy-paste artifact) that would
        # otherwise make httpx reject the URL ("missing http(s):// protocol").
        return v.strip()


class TextClassifierConfig(BaseModel):
    enabled: bool = False
    threshold: float = 0.80
    exclude: list[str] = Field(default_factory=list)
    include_only: list[str] = Field(default_factory=list)


class ImageClassifierConfig(BaseModel):
    enabled: bool = False
    action: Literal["blur", "block", "checkerboard"] = "blur"
    # NudeNet scores real-world thumbnails ~0.2-0.6, so a high threshold misses
    # most of them. 0.4 favors recall (blurring is non-destructive).
    threshold: float = 0.4
    exclude: list[str] = Field(default_factory=list)
    include_only: list[str] = Field(default_factory=list)


class SafeSearchConfig(BaseModel):
    enabled: bool = False
    block_images_tab: bool = False
    block_videos_tab: bool = False
    block_ai_tab: bool = False
    exclude: list[str] = Field(default_factory=list)
    include_only: list[str] = Field(default_factory=list)


class YouTubeConfig(BaseModel):
    enabled: bool = False
    mode: Literal["blacklist", "whitelist"] = "blacklist"
    channels: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)
    include_only: list[str] = Field(default_factory=list)
    # In whitelist mode, also block the YouTube home page / feeds (only listed
    # channels' content should be reachable).
    block_home: bool = True
    # Clean up the watch page.
    remove_comments: bool = False
    remove_recommendations: bool = False  # related-videos sidebar / autoplay


class MitmConfig(BaseModel):
    mode: Literal["exclude", "include"] = "exclude"
    sites: list[str] = Field(default_factory=list)
    # User-Agent based passthrough. TLS bypass (ignore_hosts) happens before any
    # HTTP header is visible, so this cannot skip interception — by the time the
    # User-Agent is readable the connection is already decrypted. Instead, a
    # matching request is marked passthrough so the filtering addons skip it.
    #   off     — ignore User-Agent
    #   exclude — requests whose User-Agent contains any listed token pass
    #             through unfiltered (e.g. let a specific app/device through)
    #   include — only requests whose User-Agent contains a listed token are
    #             filtered; everything else passes through
    # Tokens are matched case-insensitively as substrings.
    ua_mode: Literal["off", "exclude", "include"] = "off"
    user_agents: list[str] = Field(default_factory=list)


class UrlFilterConfig(BaseModel):
    enabled: bool = False
    allow: list[str] = Field(default_factory=list)
    block: list[str] = Field(default_factory=list)
    # Shared site categories. The custom allow/block lists take precedence; how
    # the categories themselves are applied depends on `mode`:
    #   blacklist — domains in the selected categories are blocked
    #   whitelist — only domains in the selected categories are allowed
    mode: Literal["blacklist", "whitelist"] = "blacklist"
    categories: list[str] = Field(default_factory=list)


class BlockPageConfig(BaseModel):
    template: str = "default"
    message: str = ""


class Policy(BaseModel):
    name: str
    source_ips: list[str] = Field(default_factory=list)
    doh: DohConfig = Field(default_factory=DohConfig)
    text_classifier: TextClassifierConfig = Field(default_factory=TextClassifierConfig)
    image_classifier: ImageClassifierConfig = Field(default_factory=ImageClassifierConfig)
    safesearch: SafeSearchConfig = Field(default_factory=SafeSearchConfig)
    youtube: YouTubeConfig = Field(default_factory=YouTubeConfig)
    mitm: MitmConfig = Field(default_factory=MitmConfig)
    url_filter: UrlFilterConfig = Field(default_factory=UrlFilterConfig)
    block_page: BlockPageConfig = Field(default_factory=BlockPageConfig)


class GlobalSettings(BaseModel):
    # Proxy listen endpoints — one or more "host:port". The proxy binds each
    # (mitmproxy supports multiple). e.g. ["0.0.0.0:8080", "[::]:8080"].
    proxy_listen: list[str] = Field(default_factory=lambda: ["0.0.0.0:8080"])
    # Management server bind — independent of the proxy listen settings.
    mgmt_host: str = "0.0.0.0"
    mgmt_port: int = 8000
    cert_dir: str = "./certs"
    policies_dir: str = "./policies"
    # Single logs directory; individual log files live inside it.
    logs_dir: str = "./logs"
    log_blocks: bool = True
    log_requests: bool = True
    request_log_max: int = 2000
    default_policy: str | None = None
    # Management UI authentication. password_hash/secret_key are managed
    # server-side and never sent to the browser.
    auth_enabled: bool = False
    password_hash: str = ""
    secret_key: str = ""
    # Proxy auto-config (PAC / WPAD). pac_proxy_host is the address clients
    # should be told to use; blank = derive from the request's Host header.
    # pac_direct_hosts go straight to the internet (no proxy) in the PAC.
    pac_proxy_host: str = ""
    pac_direct_hosts: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _migrate_legacy(cls, data):
        """Accept the older flat schema (proxy_port/listen_host/blocks_log_path)."""
        if not isinstance(data, dict):
            return data
        d = dict(data)
        if "proxy_listen" not in d and ("proxy_port" in d or "listen_host" in d):
            host = (d.get("listen_host") or "").strip() or "0.0.0.0"
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            d["proxy_listen"] = [f"{host}:{d.get('proxy_port', 8080)}"]
        if "mgmt_host" not in d and "listen_host" in d:
            d["mgmt_host"] = (d.get("listen_host") or "").strip() or "0.0.0.0"
        if "logs_dir" not in d and "blocks_log_path" in d:
            d["logs_dir"] = str(Path(d["blocks_log_path"]).parent) or "./logs"
        return d

    @field_validator("proxy_listen")
    @classmethod
    def _clean_listen(cls, v: list[str]) -> list[str]:
        cleaned = [e.strip() for e in v if e and e.strip()]
        return cleaned or ["0.0.0.0:8080"]

    # --- derived (not stored) -------------------------------------------------
    @property
    def blocks_log_path(self) -> str:
        return str(Path(self.logs_dir) / "blocks.jsonl")

    @property
    def request_log_path(self) -> str:
        return str(Path(self.logs_dir) / "requests.jsonl")

    @property
    def proxy_modes(self) -> list[str]:
        return [to_mitm_mode(e) for e in self.proxy_listen]

    @property
    def primary_proxy_port(self) -> int:
        for e in self.proxy_listen:
            _, p = split_hostport(e)
            if p:
                return p
        return 8080
