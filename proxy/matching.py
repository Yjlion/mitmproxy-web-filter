from __future__ import annotations
import fnmatch


def host_matches(host: str, pattern: str) -> bool:
    """Exact, *.wildcard (subdomains), or glob host match."""
    pattern = pattern.strip()
    if not pattern:
        return False
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith("." + base)
    return fnmatch.fnmatch(host, pattern)


def url_matches(host: str, url: str, pattern: str) -> bool:
    """Patterns containing '/' match the full URL (glob or prefix); otherwise
    treated as a host pattern. Supports domains AND URLs with a path.

    Path patterns may include or omit the scheme (http:// / https://). A
    scheme-less pattern like 'example.com/path' is checked against both the
    full URL and against the URL with its scheme stripped."""
    pattern = pattern.strip()
    if not pattern:
        return False
    if "/" in pattern:
        if fnmatch.fnmatch(url, pattern) or url.startswith(pattern):
            return True
        # Also try matching against the URL with scheme stripped so that
        # 'example.com/path' matches 'https://example.com/path/file'.
        for prefix in ("https://", "http://"):
            if url.startswith(prefix):
                url_no_scheme = url[len(prefix):]
                if fnmatch.fnmatch(url_no_scheme, pattern) or url_no_scheme.startswith(pattern):
                    return True
                break
        return False
    return host_matches(host, pattern)


def url_in_list(host: str, url: str, patterns) -> bool:
    return any(url_matches(host, url, p) for p in patterns if p and p.strip())


def domain_in_list(host: str, patterns) -> bool:
    """Domain-only suffix match (exact host or any subdomain). Strips a leading
    '*.' so '*.example.com' and 'example.com' behave the same."""
    for s in patterns:
        s = (s or "").strip().lstrip("*.")
        if s and (host == s or host.endswith("." + s)):
            return True
    return False
