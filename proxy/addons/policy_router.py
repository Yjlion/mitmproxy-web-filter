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
from shared import neighbors

logger = logging.getLogger(__name__)

_policies: list[Policy] = []
_settings: GlobalSettings = GlobalSettings()
_project_root: Path = Path(__file__).parent.parent.parent


def load_settings() -> GlobalSettings:
    path = _project_root / "config" / "settings.json"
    if path.exists():
        return GlobalSettings.model_validate_json(path.read_text(encoding="utf-8-sig"))
    return GlobalSettings()


def load_policies(policies_dir: Path) -> list[Policy]:
    loaded: list[Policy] = []
    for f in sorted(policies_dir.glob("*.json")):
        try:
            # utf-8-sig transparently strips a UTF-8 BOM, which hand-edited
            # files (e.g. saved by PowerShell's Set-Content -Encoding utf8)
            # often carry and which would otherwise make json.loads fail.
            data = json.loads(f.read_text(encoding="utf-8-sig"))
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
    """Match a client to a policy by specificity, most specific first:

      0. MAC match (resolved from the client IP via the OS neighbor table).
      1. Exact single-IP match.
      2. CIDR block match (the narrowest matching block wins — i.e. the one
         with the longest prefix; ties broken by file sort order).
      3. Catch-all: a policy with empty source_ips.

    Within a tier, policies are considered in file sort order (first wins).
    A policy with `schedule.enabled` is skipped when the current time falls
    outside all its active_windows — matching falls through to the next
    candidate in the same tier, or to lower tiers."""
    addrs = _client_addrs(client_ip)
    if not addrs:
        return None

    # Tier 0: MAC match — the most stable identifier (survives DHCP IP changes).
    # Best-effort: only resolves for devices on the proxy's own L2 segment;
    # otherwise lookup() returns None and we fall through to IP matching.
    if any(policy.source_macs for policy in _policies):
        mac = neighbors.lookup(client_ip)
        if mac:
            for policy in _policies:
                if mac in policy.source_macs and policy.schedule.is_active_now():
                    return policy

    # Tier 1: exact single-IP match.
    for policy in _policies:
        if not policy.schedule.is_active_now():
            continue
        for src in policy.source_ips:
            if "/" in src:
                continue
            try:
                target = ip_address(src)
            except ValueError:
                continue
            if any(a == target for a in addrs):
                return policy

    # Tier 2: CIDR block match — prefer the narrowest (longest-prefix) block.
    best_policy: Policy | None = None
    best_prefixlen = -1
    for policy in _policies:
        if not policy.schedule.is_active_now():
            continue
        for src in policy.source_ips:
            if "/" not in src:
                continue
            try:
                net = ip_network(src, strict=False)
            except ValueError:
                continue
            if any(a.version == net.version and a in net for a in addrs):
                if net.prefixlen > best_prefixlen:
                    best_policy = policy
                    best_prefixlen = net.prefixlen
    if best_policy is not None:
        return best_policy

    # Tier 3: catch-all (empty source_ips).
    for policy in _policies:
        if not policy.source_ips and policy.schedule.is_active_now():
            return policy

    return None


class PolicyRouter:
    def load(self, loader):
        global _settings
        _settings = load_settings()

        try:
            from shared import categories as cats
            cats.configure(getattr(_settings, "categories_dir", "./categories"))
        except Exception:
            pass

        if _settings.log_blocks or _settings.log_requests:
            from shared import logstore
            logstore.configure(
                _settings.db_path,
                _settings.log_retention_days,
                log_requests=_settings.log_requests,
                log_blocks=_settings.log_blocks,
            )
            logstore.migrate_legacy(
                _project_root / _settings.logs_dir
            )

    def running(self):
        global _policies, _settings
        _settings = load_settings()
        try:
            from shared import categories as cats
            cats.configure(getattr(_settings, "categories_dir", "./categories"))
        except Exception:
            pass
        policies_dir = _project_root / _settings.policies_dir
        _policies = load_policies(policies_dir)
        logger.info(f"[policy_router] Loaded {len(_policies)} policies from {policies_dir}")
        # Keep a strong reference to the task. In Python 3.12+ asyncio only holds
        # a weak reference to tasks, so without this the GC can destroy the watcher
        # before it ever fires.
        self._watch_task = asyncio.ensure_future(self._watch(policies_dir))

        # Seed ignore_hosts from policies (MITM exclusions)
        self._sync_ignore_hosts()

    def request(self, flow: http.HTTPFlow) -> None:
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else ""
        flow.metadata["policy"] = get_policy(client_ip)

    async def _watch(self, policies_dir: Path) -> None:
        try:
            from watchfiles import awatch
        except ImportError:
            return  # watchfiles not installed; hot-reload disabled

        while True:
            try:
                async for _ in awatch(str(policies_dir)):
                    global _policies
                    _policies = load_policies(policies_dir)
                    logger.info(f"[policy_router] Reloaded {len(_policies)} policies")
                    self._sync_ignore_hosts()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("[policy_router] Watcher error: %s; restarting in 5s", exc)
                await asyncio.sleep(5)

    def _sync_ignore_hosts(self) -> None:
        domains: set[str] = set()
        for policy in _policies:
            if policy.mitm.mode == "exclude":
                for site in policy.mitm.sites:
                    domains.add(site.lstrip("*.").lower())

        try:
            if not domains:
                ctx.options.ignore_hosts = []
                return
            # Anchor each domain so "example.com" matches host/subdomains but not
            # "notexample.com": (?:^|\.)example\.com(?::\d+)?$ over all domains.
            alts = "|".join(sorted(d.replace(".", r"\.") for d in domains))
            pattern = r"(?:^|\.)(?:" + alts + r")(?::\d+)?$"
            ctx.options.ignore_hosts = [pattern]
        except Exception:
            pass
