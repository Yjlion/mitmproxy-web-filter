#!/usr/bin/env python3
"""Scan a URL for NSFW content without going through the proxy.

Usage:
  python scripts/scan_url.py <url> [--text-threshold 0.80] \
      [--image-threshold 0.4] [--max-images 50] [--timeout 10]

The scanner fetches the URL directly (trust_env=False), classifies it, and
prints a human-readable verdict:

* For an image URL  — NudeNet detection verdict.
* For an HTML page  — text-classifier verdict + per-image table.
* For anything else — the raw Content-Type.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Ensure the repo root is importable so shared/ and proxy/ resolve correctly.
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.nsfw_scan import scan_url_sync  # noqa: E402


def _top_detections(detections: list[dict], n: int = 3) -> str:
    """Return a short string listing the top-n NudeNet detections by score."""
    if not detections:
        return "(none)"
    top = sorted(detections, key=lambda d: d.get("score", 0), reverse=True)[:n]
    return ", ".join(
        f"{d.get('class', '?')} {d.get('score', 0):.2f}" for d in top
    )


def _print_result(result: dict) -> None:
    kind = result.get("type", "unknown")

    if kind == "error":
        print(f"[ERROR] {result.get('error', 'unknown error')}")
        return

    print(f"Type     : {kind}")
    print(f"URL      : {result.get('url', '')}")

    if kind == "image":
        nsfw = result.get("nsfw", False)
        label = "NSFW" if nsfw else "clean"
        skipped = result.get("skipped")
        print(f"Verdict  : {label}" + (f" (skipped: {skipped})" if skipped else ""))
        print(f"Threshold: {result.get('image_threshold', 0.4)}")
        print(f"Detections: {_top_detections(result.get('detections', []))}")
        return

    if kind == "page":
        text = result.get("text", {})
        t_nsfw = text.get("nsfw", False)
        t_label = "NSFW" if t_nsfw else "clean"
        print(f"Text     : {t_label}  (keyword_score={text.get('keyword_score', 0):.2f},"
              f" threshold={text.get('threshold', 0.8):.2f})")
        images = result.get("images", [])
        n_nsfw = sum(1 for img in images if img.get("nsfw"))
        print(f"Images   : {len(images)} fetched, {n_nsfw} NSFW")
        if images:
            print()
            # Column widths
            url_w = min(60, max((len(img.get("url", "")) for img in images), default=3))
            header = f"{'URL':<{url_w}}  {'NSFW':<5}  Top detections"
            print(header)
            print("-" * len(header))
            for img in images:
                url = img.get("url", "")
                if len(url) > url_w:
                    url = url[: url_w - 3] + "..."
                nsfw_str = "YES" if img.get("nsfw") else "no"
                err = img.get("error")
                skipped = img.get("skipped")
                if err:
                    det_str = f"[error: {err[:40]}]"
                elif skipped:
                    det_str = f"[skipped: {skipped}]"
                else:
                    det_str = _top_detections(img.get("detections", []))
                print(f"{url:<{url_w}}  {nsfw_str:<5}  {det_str}")
        return

    if kind == "other":
        print(f"Content-Type: {result.get('content_type', 'unknown')}")
        print("(No classification performed for this content type.)")
        return

    # Fallback
    import json
    print(json.dumps(result, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("url", help="URL to scan")
    parser.add_argument(
        "--text-threshold",
        type=float,
        default=0.80,
        metavar="T",
        help="ML confidence threshold for text classification (default: 0.80)",
    )
    parser.add_argument(
        "--image-threshold",
        type=float,
        default=0.4,
        metavar="T",
        help="NudeNet score threshold for image classification (default: 0.4)",
    )
    parser.add_argument(
        "--max-images",
        type=int,
        default=50,
        metavar="N",
        help="Maximum number of images to classify on an HTML page (default: 50)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        metavar="SECS",
        help="HTTP request timeout in seconds (default: 10)",
    )
    args = parser.parse_args()

    result = scan_url_sync(
        args.url,
        text_threshold=args.text_threshold,
        image_threshold=args.image_threshold,
        max_images=args.max_images,
        timeout=args.timeout,
    )
    _print_result(result)


if __name__ == "__main__":
    main()
