#!/usr/bin/env python3
"""Launch mitmdump via its Python entrypoint.

Invoking mitmdump this way (instead of the `mitmdump` console script) lets a
bundled, relocatable Python runtime work without depending on the absolute
shebang paths that pip bakes into console scripts. All command-line arguments
are forwarded to mitmdump unchanged.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mitmproxy.tools.main import mitmdump

if __name__ == "__main__":
    mitmdump()  # parses sys.argv[1:]
