#!/usr/bin/env bash
# build_tailwind.sh — Regenerate management/ui/tailwind.css using the Tailwind v3 standalone binary.
# Run from the repo root. Idempotent: skips re-download if the binary is already cached.
set -euo pipefail

VERSION="v3.4.17"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/tailwindcss"
BIN="$CACHE_DIR/tailwindcss-$VERSION"

mkdir -p "$CACHE_DIR"

if [ ! -f "$BIN" ]; then
  OS="$(uname -s)"
  ARCH="$(uname -m)"

  if [ "$OS" = "Darwin" ]; then
    if [ "$ARCH" = "arm64" ]; then
      ASSET="tailwindcss-macos-arm64"
    else
      ASSET="tailwindcss-macos-x64"
    fi
  elif [ "$OS" = "Linux" ]; then
    if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
      ASSET="tailwindcss-linux-arm64"
    else
      ASSET="tailwindcss-linux-x64"
    fi
  else
    echo "Unsupported OS: $OS" >&2
    exit 1
  fi

  URL="https://github.com/tailwindlabs/tailwindcss/releases/download/$VERSION/$ASSET"
  echo "Downloading Tailwind CSS standalone binary $VERSION ($ASSET) ..."
  curl -fsSL "$URL" -o "$BIN"
  chmod +x "$BIN"
  echo "Download complete."
else
  echo "Tailwind binary already cached at $BIN"
fi

echo "Building management/ui/tailwind.css ..."
"$BIN" \
  -c management/ui/tailwind.config.js \
  -i management/ui/tailwind.input.css \
  -o management/ui/tailwind.css \
  --minify

SIZE=$(wc -c < management/ui/tailwind.css)
echo "Done. management/ui/tailwind.css regenerated (${SIZE} bytes)."
