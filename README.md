# WebFilter Proxy

A mitmproxy-based web filtering proxy with per-source-IP policies and a web
management UI. Each policy is a JSON file and is matched to clients by source IP
(IPv4/IPv6, CIDR supported).

> ⚠️ **Disclaimer:** This project is "vibe coded" — largely built with AI
> assistance (Claude Code). Review and test it before relying on it; it
> intercepts TLS and filters live network traffic. Provided **as-is with no
> warranty**. See [DISCLAIMER.md](DISCLAIMER.md).

## Filtering components (per policy, individually toggleable)

- **URL filter** — allow / block lists (exact, `*.wildcard`, URL globs) plus shared
  **site categories** in blacklist (block listed categories) or whitelist (allow
  only listed categories) mode. The custom allow / block lists take precedence.
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
- **MITM control** — include/exclude sites from TLS interception (e.g. bypass
  banking sites).
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
2. Point your device/browser proxy at **`<host>:8080`**, or use automatic proxy
   configuration with **http://`<host>`:8000/proxy.pac** (also served at
   `/wpad.dat` for WPAD auto-discovery). Set the advertised host and any bypassed
   hosts under **Settings → Proxy Auto-Config**.
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

## Docker

A single container runs both the filtering proxy (port 8080) and the management UI
(port 8000). State lives in mounted volumes (`config/`, `certs/`, `policies/`,
`logs/`, `models/`) so it survives image upgrades.

### Run the published image (GitHub Container Registry)

Images are pushed to GHCR on every release tag — `:latest`, `:0.4` (major.minor),
and `:0.4.0` (exact version):

```bash
docker run -d --name webfilter-proxy \
  -p 8080:8080 -p 8000:8000 \
  -v "$PWD/config:/app/config" \
  -v "$PWD/certs:/app/certs" \
  -v "$PWD/policies:/app/policies" \
  -v "$PWD/logs:/app/logs" \
  -v "$PWD/models:/app/models" \
  ghcr.io/yjlion/mitmproxy-web-filter:latest
```

Published images ship with site-category blocklists pre-baked at build time. To
refresh them in a running container, mount a host `categories/` directory and run
the update script:

```bash
# Linux / macOS
docker run -d --name webfilter-proxy \
  -p 8080:8080 -p 8000:8000 \
  -v "$PWD/config:/app/config" \
  -v "$PWD/certs:/app/certs" \
  -v "$PWD/policies:/app/policies" \
  -v "$PWD/logs:/app/logs" \
  -v "$PWD/models:/app/models" \
  -v "$PWD/categories:/app/categories" \   
  ghcr.io/yjlion/mitmproxy-web-filter:latest

# Then refresh the lists on the host and they are live immediately:
bash scripts/update_categories.sh          # Linux / macOS
scripts\update_categories.ps1             # Windows
```

Alternatively, simply pull a newer image — published images always include
up-to-date lists baked in at release time.

### Host networking (Linux)

With default bridge networking all clients appear as the Docker gateway IP, so
per-source-IP policies cannot distinguish between clients. Use `--network host`
so the proxy sees real client IPs:

```bash
docker run -d --name webfilter-proxy \
  --network host \
  -v "$PWD/config:/app/config" \
  -v "$PWD/certs:/app/certs" \
  -v "$PWD/policies:/app/policies" \
  -v "$PWD/logs:/app/logs" \
  -v "$PWD/models:/app/models" \
  -v "$PWD/categories:/app/categories" \   
  ghcr.io/yjlion/mitmproxy-web-filter:latest
```

> Note: `--network host` is Linux-only. `-p` port mappings are unnecessary and
> ignored with host networking — ports 8080 and 8000 bind directly on the host.

### Build locally with Docker Compose

```bash
docker compose up -d        # build the image + start in the background
docker compose logs -f      # follow logs
docker compose down         # stop
```

Then open the management UI at **http://localhost:8000**, point each device's proxy
at **`<host>:8080`** (or use `http://<host>:8000/proxy.pac`), and install the CA
certificate from **Settings → CA Certificate**.

> Note: published images ship with site-category blocklists pre-baked. To refresh
> them without pulling a new image, mount a host `categories/` directory at
> `/app/categories` and run `scripts/update_categories.sh` (Linux) or
> `scripts\update_categories.ps1` (Windows) on the host.

## Configuration

- `config/settings.json` — global config (proxy listen addresses, management host/port,
  logs dir, auth). Not committed (holds the password hash); copy `settings.example.json`
  to create it, or just save once from the Settings page.
- `policies/*.json` — one file per policy, hot-reloaded by the proxy on change.
- `categories/` — shared site-category blocklists (one folder per category, each
  with a `domains` file). Populate / refresh them from the IPFire squidguard list:

  ```bash
  # Linux / macOS
  scripts/update_categories.sh                             # download + (re)build all categories
  scripts/update_categories.sh --keep porn,gambling,ads   # subset only

  # Windows
  scripts\update_categories.ps1
  scripts\update_categories.ps1 -Keep porn,gambling,ads
  ```

  Run it on a schedule (cron / Task Scheduler) to keep lists current. Policies
  reference categories by name under the URL filter (blacklist or whitelist
  mode); the policy's own custom allow / block lists take precedence.

See [CLAUDE.md](CLAUDE.md) for architecture details.

## Releases

Pushing a `v*` tag (or running the **build-archives** workflow manually) builds
self-contained archives for Linux and Windows with a relocatable Python runtime and all
dependencies included, and publishes the Docker image to
`ghcr.io/yjlion/mitmproxy-web-filter` (see [Docker](#docker)).
