from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import time as _time
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

    try:
        parsed = urlparse(s)
        host = parsed.hostname
    except ValueError as e:
        raise InvalidURL(f"Invalid URL: {e}.") from e
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise InvalidURL(f"Unsupported URL scheme: {parsed.scheme!r}.")
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
    host_text = f"[{host}]" if ":" in host else host
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
    # any colon at this point, require an actual IPv6 literal. This keeps
    # bracketed garbage like [not::ip] or IPvFuture forms from slipping through
    # as "valid" hosts and failing later in less controlled places.
    if ":" in host:
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            return False
        return True
    if _IPV4_RE.match(host):
        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            return False
        return True
    # Reject IPv4-like numeric shorthands / legacy forms (e.g. 127.1,
    # 010.000.000.001) rather than treating them as DNS hostnames. Different
    # resolvers normalize these differently, which is especially risky on the
    # web surface's SSRF boundary.
    if re.fullmatch(r"(?:\d+\.)+\d+", host):
        return False
    if _HOSTNAME_RE.match(host):
        return True
    return False


# SSRF gate. Used by the web surface only — the CLI is a local tool whose
# operator may legitimately point it at internal hosts.
_DNS_CACHE: dict[str, tuple[tuple[str, ...], float]] = {}
_DNS_CACHE_TTL = 30.0

# Hostnames that always resolve to cloud-provider metadata services.
# Block by name (in case DNS is intercepted or proxied) in addition to
# the IP-range checks below.
_BLOCKED_HOSTS = frozenset({
    "metadata.google.internal",
    "metadata.goog",
    "metadata.aws.internal",
    "instance-data",
    "instance-data.ec2.internal",
})


def _is_disallowed_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


async def assert_publicly_routable(url: str) -> None:
    """Reject URLs whose host is/resolves to a private, loopback, link-local,
    multicast, or reserved address.

    Defends the web surface against SSRF: a user can submit
    ``http://127.0.0.1:6379`` (Redis), ``http://169.254.169.254`` (cloud
    metadata service), ``http://10.0.0.1``, etc., and the scanners would
    otherwise issue real HTTP requests to those internal hosts and reflect
    the responses into the public report.

    Returns None on success; raises InvalidURL with a generic message on
    rejection (intentionally vague to avoid fingerprinting internal topology).

    Async because uvicorn runs a single event loop: a synchronous
    ``socket.getaddrinfo`` here would stall every concurrent scan, the polling
    endpoint, and the SSRF redirect-hook (which runs once per outbound request
    × every in-flight scan) for the full DNS lookup. ``loop.getaddrinfo``
    dispatches to a thread executor so the loop keeps running.

    Should be called only from the web layer; the CLI is local and its operator
    may legitimately scan internal hosts.
    """
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise InvalidURL("URL is missing a hostname.")

    if host.lower() in _BLOCKED_HOSTS:
        raise InvalidURL("This URL is not allowed.")

    # Literal IP: check directly, no DNS.
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if _is_disallowed_ip(ip):
            raise InvalidURL("This URL is not allowed.")
        return

    # Hostname: resolve once (cached ~30s) and reject if any resolved IP is
    # disallowed. CDNs typically return multiple public IPs; rejecting on
    # *any* private-range hit is intentional — don't try to be clever about
    # split-horizon DNS.
    now = _time.time()
    cached = _DNS_CACHE.get(host)
    if cached and cached[1] > now:
        ips = cached[0]
    else:
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(host, None)
        except socket.gaierror as e:
            raise InvalidURL(f"Could not resolve hostname: {host!r}.") from e
        ips = tuple({info[4][0] for info in infos})  # dedupe across families
        _DNS_CACHE[host] = (ips, now + _DNS_CACHE_TTL)

    for ip_str in ips:
        try:
            resolved = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _is_disallowed_ip(resolved):
            raise InvalidURL("This URL is not allowed.")
