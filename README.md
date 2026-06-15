# WebFilter Proxy

A mitmproxy-based web filtering proxy with per-source-IP policies and a web
management UI. Each policy is a JSON file and is matched to clients by source IP
(IPv4/IPv6, CIDR supported).

## Filtering components (per policy, individually toggleable)

- **URL filter** — allow / block lists (exact, `*.wildcard`, URL globs); allow wins.
- **DOH** — checks each domain against a DNS-over-HTTPS resolver (NextDNS, Cloudflare,
  CleanBrowsing, AdGuard, …). Detects blocks via NXDOMAIN, sinkhole IPs, RFC 8914
  Extended DNS Errors, and provider block-page IPs.
- **SafeSearch** — enforces SafeSearch on Google/Bing/DuckDuckGo/Yahoo; can block the
  image / video / AI tabs.
- **YouTube** — block or allow specific channels (by ID, @handle, or name); works on
  the watch page and the in-app player API.
- **Adult text classifier** — blocks pages with adult text.
- **Image classifier** — NSFW detection (NudeNet); blur the whole image, replace with a
  checkerboard placeholder, or blank it.
- **MITM control** — include/exclude sites from TLS interception.
- **Custom block page** per policy.

The management UI (dashboard, policy editor, settings) runs separately from the proxy
and can be password-protected.

## Quick start (release archive — runtime + dependencies bundled)

Download the archive for your OS from [Releases](../../releases), extract, and run —
no Python install required:

```bash
# Linux
tar xzf web-filter-proxy-linux-x86_64.tar.gz
cd web-filter-proxy
./start.sh
```

```bat
:: Windows — extract the .zip, then
start.bat
```

Then:
1. Open the management UI at **http://localhost:8000**.
2. Point your device/browser proxy at **`<host>:8080`**.
3. Install the CA certificate (auto-generated in `certs/` on first run) on client
   devices — download it from **Settings → CA Certificate**.

## Run from source (development)

```bash
./install.sh      # Linux  (or install.bat on Windows) — creates .venv, installs deps
./start.sh        # or start.bat
```

Run the tests:

```bash
.venv/bin/pytest tests/ -v
```

## Configuration

- `config/settings.json` — global config (proxy listen addresses, management host/port,
  logs dir, auth). Not committed (holds the password hash); copy `settings.example.json`
  to create it, or just save once from the Settings page.
- `policies/*.json` — one file per policy, hot-reloaded by the proxy on change.

See [CLAUDE.md](CLAUDE.md) for architecture details.

## Releases

Pushing a `v*` tag (or running the **build-archives** workflow manually) builds
self-contained archives for Linux and Windows with a relocatable Python runtime and all
dependencies included.
