from __future__ import annotations
import asyncio
import json
import logging
import sys
from ipaddress import ip_address, ip_network
from pathlib import Path

from mitmproxy import ctx, http

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from shared.models import Policy, GlobalSettings

logger = logging.getLogger(__name__)

_policies: list[Policy] = []
_settings: GlobalSettings = GlobalSettings()
_project_root: Path = Path(__file__).parent.parent.parent


def load_settings() -> GlobalSettings:
    path = _project_root / "config" / "settings.json"
    if path.exists():
        return GlobalSettings.model_validate_json(path.read_text())
    return GlobalSettings()


def load_policies(policies_dir: Path) -> list[Policy]:
    loaded: list[Policy] = []
    for f in sorted(policies_dir.glob("*.json")):
        try:
            data = json.loads(f.read_text())
            loaded.append(Policy.model_validate(data))
        except Exception as e:
            logger.warning("Failed to load policy %s: %s", f.name, e)
    return loaded


def _client_addrs(client_ip: str):
    """Candidate addresses for a client. IPv6 and IPv4 are handled natively.
    When the proxy listens dual-stack, IPv4 clients appear as IPv4-mapped IPv6
    (e.g. ::ffff:192.168.1.5); we also expose the unwrapped IPv4 address so a
    policy written as 192.168.1.0/24 still matches such a client."""
    # Strip a zone id (e.g. fe80::1%eth0) which ip_address can't parse.
    client_ip = client_ip.split("%", 1)[0]
    try:
        addr = ip_address(client_ip)
    except ValueError:
        return []
    addrs = [addr]
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addrs.append(mapped)
    return addrs


def get_policy(client_ip: str) -> Policy | None:
    addrs = _client_addrs(client_ip)
    if not addrs:
        return None

    for policy in _policies:
        for src in policy.source_ips:
            try:
                if "/" in src:
                    net = ip_network(src, strict=False)
                    if any(a.version == net.version and a in net for a in addrs):
                        return policy
                else:
                    target = ip_address(src)
                    if any(a == target for a in addrs):
                        return policy
            except ValueError:
                continue

    # Fall back to default policy (empty source_ips means "catch-all")
    for policy in _policies:
        if not policy.source_ips:
            return policy

    return None


class PolicyRouter:
    def load(self, loader):
        global _settings
        _settings = load_settings()

        from proxy.block_page import init_logging
        if _settings.log_blocks:
            init_logging(_settings.blocks_log_path)

        from proxy.request_log import init as init_request_log
        if _settings.log_requests:
            init_request_log(_settings.request_log_path, _settings.request_log_max)

    def running(self):
        global _policies, _settings
        policies_dir = _project_root / _settings.policies_dir.lstrip("./")
        _policies = load_policies(policies_dir)
        logger.info(f"[policy_router] Loaded {len(_policies)} policies from {policies_dir}")
        asyncio.ensure_future(self._watch(policies_dir))

        # Seed ignore_hosts from policies (MITM exclusions)
        self._sync_ignore_hosts()

    def request(self, flow: http.HTTPFlow) -> None:
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else ""
        flow.metadata["policy"] = get_policy(client_ip)

    async def _watch(self, policies_dir: Path) -> None:
        try:
            from watchfiles import awatch
            async for _ in awatch(str(policies_dir)):
                global _policies
                _policies = load_policies(policies_dir)
                logger.info(f"[policy_router] Reloaded {len(_policies)} policies")
                self._sync_ignore_hosts()
        except ImportError:
            pass  # watchfiles not installed; hot-reload disabled

    def _sync_ignore_hosts(self) -> None:
        excluded: set[str] = set()
        for policy in _policies:
            if policy.mitm.mode == "exclude":
                for site in policy.mitm.sites:
                    excluded.add(site.lstrip("*.").replace(".", r"\."))
        if excluded:
            pattern = "(" + "|".join(excluded) + ")"
            try:
                ctx.options.ignore_hosts = [pattern]
            except Exception:
                pass
