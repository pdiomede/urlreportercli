from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

import httpx

from ._retry import RetryExhausted, describe_exc, retry_request
from .base import Finding, ScanResult

log = logging.getLogger(__name__)

# (provider name, list of (header-name, optional-substring-match)).
# A header match alone is enough; substring is checked only when given.
CDN_FINGERPRINTS: list[tuple[str, list[tuple[str, str | None]]]] = [
    ("Cloudflare", [("cf-ray", None), ("cf-cache-status", None), ("server", "cloudflare")]),
    ("Akamai",     [("x-akamai-transformed", None), ("server", "akamaighost"), ("x-akamai-request-id", None)]),
    ("Fastly",     [("x-served-by", "cache-"), ("x-fastly-request-id", None), ("server", "fastly")]),
    ("AWS CloudFront", [("x-amz-cf-id", None), ("x-amz-cf-pop", None), ("via", "cloudfront")]),
    ("Google Cloud CDN / GFE", [("via", "google"), ("server", "gfe"), ("server", "gws")]),
    ("Azure CDN / Front Door", [("x-azure-ref", None), ("x-msedge-ref", None), ("x-cache", "azure")]),
    ("Sucuri",     [("server", "sucuri"), ("x-sucuri-id", None), ("x-sucuri-cache", None)]),
    ("Imperva",    [("x-iinfo", None), ("x-cdn", "imperva")]),
    ("KeyCDN",     [("server", "keycdn"), ("x-edge-location", None)]),
    ("StackPath",  [("server", "netdna-cache"), ("x-sp-edge", None), ("x-hw", None)]),
    ("BunnyCDN",   [("server", "bunnycdn"), ("cdn-pullzone", None)]),
    ("CDN77",      [("server", "cdn77"), ("x-77-cache", None)]),
    ("Vercel",     [("server", "vercel"), ("x-vercel-id", None), ("x-vercel-cache", None)]),
    ("Netlify",    [("server", "netlify"), ("x-nf-request-id", None)]),
    ("GitHub Pages", [("server", "github.com"), ("x-github-request-id", None)]),
    ("Varnish (origin or CDN)", [("via", "varnish"), ("x-varnish", None), ("server", "varnish")]),
    # Note: a bare `Via` header is intentionally NOT treated as a CDN signal.
    # RFC 7230 §5.7.1 requires every proxy in the chain to add a Via entry,
    # including forward proxies and non-CDN reverse proxies. Matching on it
    # produced false positives (corporate proxies counting as CDN, +60 score).
]

RATE_LIMIT_HEADERS = (
    "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
    "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset",
    "retry-after",
)

CACHE_HEADERS = (
    "cache-control", "cdn-cache-control", "surrogate-control",
    "x-cache", "x-cache-hits", "age",
)


def _detect_cdn(headers: httpx.Headers) -> list[str]:
    lower = {k.lower(): v.lower() for k, v in headers.items()}
    hits: list[str] = []
    for provider, sigs in CDN_FINGERPRINTS:
        for h, needle in sigs:
            if h not in lower:
                continue
            if needle is None or needle in lower[h]:
                hits.append(provider)
                break
    # de-dupe while keeping order, prefer the first specific match
    seen: set[str] = set()
    unique = []
    for h in hits:
        if h not in seen:
            seen.add(h)
            unique.append(h)
    return unique


def _has_useful_cache(headers: httpx.Headers) -> tuple[bool, str]:
    cc = headers.get("cache-control", "").lower()
    if "no-store" in cc or "private" in cc:
        return False, f"cache-control: {cc}"
    m = re.search(r"(s-maxage|max-age)\s*=\s*(\d+)", cc)
    if m and int(m.group(2)) > 0:
        return True, f"cache-control: {cc.strip()}"
    age_raw = headers.get("age")
    if age_raw:
        try:
            if int(age_raw) > 0:
                return True, f"age: {age_raw}"
        except ValueError:
            pass
    if "x-cache" in {k.lower() for k in headers.keys()}:
        x_cache = headers.get("x-cache", "")
        if "hit" in x_cache.lower():
            return True, f"x-cache: {x_cache}"
    return False, cc or "(none)"


class DoSPostureScanner:
    """Passive DoS / DDoS posture check.

    Makes a single GET to the URL and inspects the response headers for
    signals that the host is fronted by a CDN/WAF, has cacheable responses,
    and advertises rate limits. Generates **no load**.
    """

    name = "DoS posture"
    config_key = "dos_posture"

    async def scan(self, url: str, *, client: httpx.AsyncClient) -> ScanResult:
        host = urlparse(url).hostname or ""
        link = url

        try:
            resp = await retry_request(
                lambda: client.get(url, follow_redirects=True, timeout=20.0),
                label=self.name, logger=log,
            )
        except RetryExhausted as e:
            log.error("%s: %s", self.name, e)
            return ScanResult(scanner=self.name, ok=False, error=str(e), link=link)
        except httpx.HTTPError as e:
            return ScanResult(scanner=self.name, ok=False, error=describe_exc(e), link=link)

        cdns = _detect_cdn(resp.headers)
        cache_ok, cache_detail = _has_useful_cache(resp.headers)
        rate_hits = sorted(
            h for h in resp.headers.keys() if h.lower() in RATE_LIMIT_HEADERS
        )

        score = 0
        if cdns:
            score += 60
        if cache_ok:
            score += 25
        if rate_hits:
            score += 15

        if score >= 95:
            grade = "A+"
        elif score >= 85:
            grade = "A"
        elif score >= 70:
            grade = "B"
        elif score >= 55:
            grade = "C"
        elif score >= 35:
            grade = "D"
        else:
            grade = "F"

        findings: list[Finding] = []

        if cdns:
            findings.append(Finding(
                severity="info",
                title="CDN / edge proxy detected",
                detail="Provider(s): " + ", ".join(cdns),
                recommendation=None,
            ))
        else:
            findings.append(Finding(
                severity="medium",
                title="No CDN/WAF detected from response headers",
                detail="Origin appears to serve traffic directly. Without an edge proxy, even moderate traffic spikes hit the origin.",
                recommendation="Front the site with a CDN that absorbs L7 floods (Cloudflare, Fastly, CloudFront, Akamai, etc).",
            ))

        if cache_ok:
            findings.append(Finding(
                severity="info",
                title="Cacheable response",
                detail=cache_detail,
                recommendation=None,
            ))
        else:
            findings.append(Finding(
                severity="low",
                title="Response not cacheable at the edge",
                detail=f"Observed: {cache_detail}",
                recommendation="Set a positive max-age / s-maxage on cacheable assets so edge POPs absorb repeat traffic.",
            ))

        if rate_hits:
            findings.append(Finding(
                severity="info",
                title="Rate-limit headers present",
                detail=", ".join(rate_hits),
                recommendation=None,
            ))
        else:
            findings.append(Finding(
                severity="low",
                title="No rate-limit headers observed on this response",
                detail="No x-ratelimit-* / ratelimit-* / retry-after seen.",
                recommendation="Advertise per-IP / per-API-key rate limits via response headers; helps clients self-throttle.",
            ))

        bits = []
        if cdns:
            bits.append(f"CDN: {cdns[0]}")
        else:
            bits.append("no CDN")
        if cache_ok:
            bits.append("cacheable")
        if rate_hits:
            bits.append("rate-limited")
        summary = "; ".join(bits)

        return ScanResult(
            scanner=self.name, ok=True, grade=grade, score=score,
            summary=summary, findings=findings, link=link,
        )
