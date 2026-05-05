from __future__ import annotations

import re
from urllib.parse import urlparse, urlunparse


class InvalidURL(ValueError):
    """Raised when user-supplied URL fails validation."""


# Reject control characters and any internal whitespace (including tab/newline).
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f\s]")

# Hostname per RFC 1123: 1-253 chars, labels 1-63, no leading/trailing hyphens.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\Z)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)

_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$"
)

# A "scheme:" prefix for any URI per RFC 3986 (used to detect non-http schemes
# entered without `://`, e.g. `javascript:alert(1)`).
_SCHEME_PREFIX_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:")

MAX_URL_LEN = 2000
ALLOWED_SCHEMES = ("http", "https")


def normalize_url(raw: str | None) -> str:
    """Strip, validate, and canonicalize a user-supplied URL.

    Rules:
      - whitespace and control chars are rejected (no smuggled CRLF / NUL);
      - `https://` is prepended when no scheme is present;
      - schemes other than http/https are rejected (`javascript:`, `data:`,
        `file:`, `ftp:`, etc.);
      - hostname must be a valid DNS name, IPv4, or bracketed IPv6;
      - total length is capped at MAX_URL_LEN.

    Raises InvalidURL with a human-readable message on rejection.
    """
    if raw is None:
        raise InvalidURL("URL is required.")
    s = raw.strip()
    if not s:
        raise InvalidURL("URL is required.")
    if len(s) > MAX_URL_LEN:
        raise InvalidURL(f"URL is too long (limit {MAX_URL_LEN} characters).")
    if _CONTROL_RE.search(s):
        raise InvalidURL("URL contains whitespace or control characters.")

    # Scheme handling. We must catch both "://" and bare "scheme:" forms,
    # otherwise `javascript:alert(1)` would slip through and become a hostname.
    if "://" in s:
        scheme = s.split("://", 1)[0].lower()
        if scheme not in ALLOWED_SCHEMES:
            raise InvalidURL(f"Unsupported URL scheme: {scheme!r}. Only http and https are allowed.")
        s = scheme + "://" + s.split("://", 1)[1]
    elif _SCHEME_PREFIX_RE.match(s):
        scheme_part, rest = s.split(":", 1)
        # Distinguish `scheme:opaque` (e.g. `javascript:alert(1)`) from a bare
        # `host:port[/path]` input (e.g. `localhost:3000`, `example.com:8080`).
        # If the segment after `:` starts with digits up to the next `/`, treat
        # it as a port and let the default-https branch handle the URL.
        rest_head = rest.split("/", 1)[0]
        if rest_head.isdigit():
            s = "https://" + s
        else:
            scheme = scheme_part.lower()
            if scheme not in ALLOWED_SCHEMES:
                raise InvalidURL(f"Unsupported URL scheme: {scheme!r}. Only http and https are allowed.")
            # Misformed `http:foo` or `https:foo` - coerce to scheme://.
            s = scheme + "://" + rest.lstrip("/")
    else:
        # No scheme present at all - default to https.
        s = "https://" + s.lstrip("/")

    parsed = urlparse(s)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise InvalidURL(f"Unsupported URL scheme: {parsed.scheme!r}.")
    host = parsed.hostname
    if not host:
        raise InvalidURL("URL is missing a hostname.")
    if not _is_valid_host(host):
        raise InvalidURL(f"Invalid hostname: {host!r}.")
    if parsed.username or parsed.password:
        raise InvalidURL("URLs with embedded credentials are not allowed.")

    # `parsed.port` raises ValueError for out-of-range numbers (e.g. :99999).
    try:
        port = parsed.port
    except ValueError as e:
        raise InvalidURL(f"Invalid port in URL: {e}.") from e

    # Strip fragment and any userinfo; keep path/query intact for the scanners.
    # IPv6 hosts must keep their brackets in the netloc (urlparse strips them
    # when returning .hostname), otherwise `[::1]:8080` becomes `::1:8080`.
    host_text = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    netloc = f"{host_text}:{port}" if port is not None else host_text
    canonical = urlunparse((
        parsed.scheme,
        netloc,
        parsed.path or "",
        parsed.params,
        parsed.query,
        "",  # drop fragment
    ))
    return canonical


def _is_valid_host(host: str) -> bool:
    # urlparse strips IPv6 brackets and returns the literal address; if there's
    # any colon at this point, treat it as an IPv6 literal (cheap accept).
    if ":" in host:
        return True
    if _IPV4_RE.match(host):
        return True
    if _HOSTNAME_RE.match(host):
        return True
    return False
