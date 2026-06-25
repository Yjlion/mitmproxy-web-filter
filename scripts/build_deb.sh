#!/usr/bin/env bash
# Build a Debian/Ubuntu .deb package for webfilter-proxy.
#
# Usage:
#   bash scripts/build_deb.sh [VERSION]
#
# VERSION defaults to the content of the VERSION file in the project root, or
# 0.0.0 if neither is provided. Strip any leading 'v' before passing.
#
# The script bundles a Python venv (built from requirements.txt) inside the
# package so the only Debian dependency is python3 + python3-venv.
#
# Requires: dpkg-deb (part of the dpkg package, available on any Debian/Ubuntu
# system), python3, python3-venv.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# ── Version ──────────────────────────────────────────────────────────────────
RAW_VERSION="${1:-}"
if [[ -z "$RAW_VERSION" ]]; then
    VERSION_FILE="$PROJECT_ROOT/VERSION"
    RAW_VERSION="$(cat "$VERSION_FILE" 2>/dev/null || echo "0.0.0")"
fi
VERSION="${RAW_VERSION#v}"   # strip leading 'v' if present

# ── Architecture ─────────────────────────────────────────────────────────────
if command -v dpkg &>/dev/null; then
    ARCH="$(dpkg --print-architecture)"
else
    # Fallback: map uname -m to Debian arch names.
    case "$(uname -m)" in
        x86_64)  ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        armv7l)  ARCH="armhf" ;;
        *)       ARCH="$(uname -m)" ;;
    esac
fi

DEB_NAME="webfilter-proxy_${VERSION}_${ARCH}.deb"
DEB_OUT="$PROJECT_ROOT/$DEB_NAME"

echo "[build_deb] version=${VERSION}  arch=${ARCH}"
echo "[build_deb] output: $DEB_OUT"

# ── Staging area ─────────────────────────────────────────────────────────────
STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

APPDIR="$STAGING/opt/webfilter-proxy"
mkdir -p "$APPDIR"

# ── Application code ─────────────────────────────────────────────────────────
echo "[build_deb] copying application code..."
cp -r "$PROJECT_ROOT"/{proxy,management,shared,scripts,categories} "$APPDIR/"
cp "$PROJECT_ROOT/requirements.txt" "$APPDIR/"

# Config: ship the deb-specific settings template as the default conffile.
mkdir -p "$APPDIR/config"
cp "$PROJECT_ROOT/packaging/settings.deb.json" "$APPDIR/config/settings.json"

# Empty writable stubs — postinst creates the real ones under /var/lib.
mkdir -p "$APPDIR/models"

# VERSION file so the app can report its version without a git checkout.
echo "$VERSION" > "$APPDIR/VERSION"

# ── Wrapper scripts for systemd ───────────────────────────────────────────────
echo "[build_deb] installing service wrapper scripts..."
cp "$PROJECT_ROOT/packaging/deb-start-proxy.sh" "$APPDIR/scripts/deb-start-proxy.sh"
cp "$PROJECT_ROOT/packaging/deb-start-mgmt.sh"  "$APPDIR/scripts/deb-start-mgmt.sh"
chmod +x "$APPDIR/scripts/deb-start-proxy.sh" "$APPDIR/scripts/deb-start-mgmt.sh"

# ── Python venv ───────────────────────────────────────────────────────────────
echo "[build_deb] building bundled venv (this may take a few minutes)..."
python3 -m venv "$APPDIR/venv"
"$APPDIR/venv/bin/pip" install --upgrade pip --quiet
"$APPDIR/venv/bin/pip" install -r "$APPDIR/requirements.txt" --quiet
# Strip __pycache__ to keep the package size down.
find "$APPDIR/venv" -name '__pycache__' -type d -prune -exec rm -rf {} + || true

# Strip __pycache__ from the app code too.
find "$APPDIR" -path "$APPDIR/venv" -prune -o -name '__pycache__' -type d -print \
    | xargs -r rm -rf || true

# ── Systemd units ─────────────────────────────────────────────────────────────
echo "[build_deb] installing systemd units..."
UNITDIR="$STAGING/lib/systemd/system"
mkdir -p "$UNITDIR"
cp "$PROJECT_ROOT/packaging/webfilter-proxy.service" "$UNITDIR/"
cp "$PROJECT_ROOT/packaging/webfilter-mgmt.service"  "$UNITDIR/"

# ── Var directories (stubs; postinst sets ownership) ─────────────────────────
mkdir -p \
    "$STAGING/var/lib/webfilter-proxy/certs" \
    "$STAGING/var/lib/webfilter-proxy/policies" \
    "$STAGING/var/lib/webfilter-proxy/logs" \
    "$STAGING/var/lib/webfilter-proxy/models" \
    "$STAGING/var/log/webfilter-proxy"

# ── Logrotate ────────────────────────────────────────────────────────────────
mkdir -p "$STAGING/etc/logrotate.d"
cp "$PROJECT_ROOT/packaging/logrotate.d/webfilter-proxy" "$STAGING/etc/logrotate.d/"

# ── DEBIAN control files ──────────────────────────────────────────────────────
echo "[build_deb] writing DEBIAN control files..."
DEBIAN_DIR="$STAGING/DEBIAN"
mkdir -p "$DEBIAN_DIR"

INSTALLED_SIZE=$(du -sk "$STAGING" | cut -f1)

sed \
    -e "s/VERSION_PLACEHOLDER/$VERSION/" \
    -e "s/ARCH_PLACEHOLDER/$ARCH/" \
    -e "s/SIZE_PLACEHOLDER/$INSTALLED_SIZE/" \
    "$PROJECT_ROOT/packaging/debian/control" > "$DEBIAN_DIR/control"

cp "$PROJECT_ROOT/packaging/debian/postinst" "$DEBIAN_DIR/postinst"
cp "$PROJECT_ROOT/packaging/debian/prerm"    "$DEBIAN_DIR/prerm"
cp "$PROJECT_ROOT/packaging/debian/conffiles" "$DEBIAN_DIR/conffiles"
chmod 755 "$DEBIAN_DIR/postinst" "$DEBIAN_DIR/prerm"

# ── Build ─────────────────────────────────────────────────────────────────────
echo "[build_deb] running dpkg-deb..."
dpkg-deb --root-owner-group --build "$STAGING" "$DEB_OUT"

SIZE_MB=$(du -sh "$DEB_OUT" | cut -f1)
echo ""
echo "  ============================================"
echo "  Package built: $DEB_NAME  ($SIZE_MB)"
echo ""
echo "  Install:  sudo dpkg -i $DEB_NAME"
echo "  Remove:   sudo apt remove webfilter-proxy"
echo "  ============================================"
