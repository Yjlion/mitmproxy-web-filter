# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install (first time)
./install.sh          # Linux
install.bat           # Windows

# Run
./start.sh            # Linux (proxy + management UI in one terminal)
start.bat             # Windows (two separate console windows)

# Tests
.venv/bin/pytest tests/ -v

# Run single test file
.venv/bin/pytest tests/test_url_filter.py -v

# Management API only (for UI dev)
.venv/bin/uvicorn management.api.main:app --reload --port 8000

# Proxy only
.venv/bin/mitmdump --set confdir=./certs --listen-port 8080 -s proxy/main.py
```

## Architecture

Two processes share the `policies/` directory:

**Proxy** (`proxy/`) — mitmproxy with custom addons, runs on port 8080.
- `proxy/main.py` — registers all addons in execution order
- `proxy/addons/policy_router.py` — runs first on every request; loads `policies/*.json`, matches source IP to policy via CIDR, attaches `flow.metadata["policy"]`; hot-reloads on file change via `watchfiles`
- `proxy/addons/*.py` — each addon reads `flow.metadata["policy"]` and applies its component if enabled
- `proxy/block_page.py` + `proxy/block_template.html` — shared block page renderer (Jinja2); also writes to `logs/blocks.jsonl`

**Management** (`management/`) — FastAPI + static UI, runs on port 8000.
- `management/api/main.py` — FastAPI app, mounts routes then serves `management/ui/` as static files
- `management/api/routes/policies.py` — CRUD for `policies/*.json`; file is the source of truth
- `management/ui/` — Vanilla JS + Alpine.js + Tailwind CSS SPA (no build step)

**Shared** (`shared/models.py`) — Pydantic v2 models used by both the proxy and management API. `Policy` is the canonical schema.

## Key Design Decisions

- **Policy = JSON file**: one file per policy in `policies/`. File name = `{safe_policy_name}.json`. Proxy watches for changes and hot-reloads without restart.
- **Source IP matching**: matched by specificity, most specific first — (1) exact single-IP match, (2) CIDR block match (the narrowest/longest-prefix matching block wins), (3) catch-all (empty `source_ips`). Within a tier, policies are checked in file sort order (first wins).
- **Addon execution order**: `policy_router` → `mitm_control` → `url_filter` → `doh_filter` → `safesearch` → `youtube_filter` → then response hooks in reverse: `text_classifier` → `image_classifier`.
- **Allow list short-circuits everything**: `url_filter.allow` match sets `flow.metadata["url_allowed"] = True`, which all other addons check and skip.
- **MITM bypass**: done via `ctx.options.ignore_hosts` (global regex), aggregated from all policies' `mitm.mode == "exclude"` lists. Per-IP TLS bypass is architecturally limited.
- **MITM passthrough (filtering skip)**: `mitm_control` marks `flow.metadata["mitm_passthrough"]` for include-mode non-listed sites and for User-Agent rules (`mitm.ua_mode` exclude/include over `mitm.user_agents`, case-insensitive substring match). This can't un-intercept TLS — the User-Agent isn't visible until after interception — it only makes filtering addons skip the flow (same gate as `url_allowed`).
- **ML dependencies are optional**: `text_classifier` works without a model (keyword regex only); `image_classifier` gracefully skips if `nudenet` fails to import. ML model for text is at `models/text_classifier.joblib`.

## Component Quick Reference

| File | Hook | Purpose |
|---|---|---|
| `policy_router.py` | `request` | Attach policy to flow |
| `mitm_control.py` | `request` | Mark passthrough for include-mode sites + User-Agent rules |
| `url_filter.py` | `request` | Block/allow URLs |
| `doh_filter.py` | `async request` | DOH domain lookup (httpx) |
| `safesearch.py` | `request` | Rewrite search URLs |
| `youtube_filter.py` | `response` | Block channels from page HTML |
| `text_classifier.py` | `response` | Adult text detection |
| `image_classifier.py` | `response` | NSFW image blur/block |
