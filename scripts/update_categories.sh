#!/usr/bin/env bash
#
# Download and (re)populate the shared site categories from the IPFire
# squidguard blocklist. Safe to run repeatedly (e.g. from cron / a scheduled
# task). Writes:
#
#   categories/<name>/domains   one domain per line (comments stripped)
#   categories/index.json       [{name, count, updated}, ...] + metadata
#
# Usage:  scripts/update_categories.sh [--url URL] [--keep CATS] [--quiet]
#   --url URL    override the source (default: IPFire squidguard.tar.gz)
#   --keep CATS  comma-separated category whitelist (default: all)
#
set -euo pipefail

URL="https://dbl.ipfire.org/lists/squidguard.tar.gz"
KEEP=""
QUIET=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --url)   URL="$2"; shift 2 ;;
    --keep)  KEEP="$2"; shift 2 ;;
    --quiet) QUIET=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

log() { [[ "$QUIET" == "1" ]] || echo "$@"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
DEST="$ROOT/categories"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

log "[categories] downloading $URL"
curl -fSL --retry 3 --connect-timeout 30 -o "$TMP/list.tar.gz" "$URL"

log "[categories] extracting"
tar xzf "$TMP/list.tar.gz" -C "$TMP"

# Find the directory that holds the per-category subdirectories (IPFire uses
# "blacklists/"; fall back to the first dir that contains */domains).
SRC=""
for cand in "$TMP/blacklists" "$TMP"/*/; do
  if compgen -G "$cand/*/domains" >/dev/null 2>&1; then SRC="${cand%/}"; break; fi
done
[[ -n "$SRC" ]] || { echo "[categories] no */domains found in archive" >&2; exit 1; }

# Build into a staging dir, then swap in atomically.
STAGE="$TMP/stage"
mkdir -p "$STAGE"
INDEX_ITEMS=()
UPDATED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

shopt -s nullglob
for catdir in "$SRC"/*/; do
  name="$(basename "$catdir")"
  [[ -f "$catdir/domains" ]] || continue
  if [[ -n "$KEEP" ]] && [[ ",$KEEP," != *",$name,"* ]]; then continue; fi
  mkdir -p "$STAGE/$name"
  # Strip comments and blank lines; normalise to lowercase; de-dupe; sort.
  grep -vE '^[[:space:]]*(#|$)' "$catdir/domains" \
    | tr 'A-Z' 'a-z' | tr -d '\r' | sort -u > "$STAGE/$name/domains"
  count="$(wc -l < "$STAGE/$name/domains" | tr -d ' ')"
  INDEX_ITEMS+=("{\"name\":\"$name\",\"count\":$count,\"updated\":\"$UPDATED\"}")
  log "$(printf '[categories] %-12s %8s domains' "$name" "$count")"
done

[[ ${#INDEX_ITEMS[@]} -gt 0 ]] || { echo "[categories] nothing populated" >&2; exit 1; }

IFS=,; printf '{\n  "source": "%s",\n  "updated": "%s",\n  "categories": [%s]\n}\n' \
  "$URL" "$UPDATED" "${INDEX_ITEMS[*]}" > "$STAGE/index.json"; unset IFS

mkdir -p "$DEST"
# Swap: move new category dirs + index into place (replace existing).
for d in "$STAGE"/*/; do
  name="$(basename "$d")"
  rm -rf "$DEST/$name"
  mv "$d" "$DEST/$name"
done
mv -f "$STAGE/index.json" "$DEST/index.json"

log "[categories] done -> $DEST"
