from __future__ import annotations

import logging
from urllib.parse import urlparse

import httpx

from ._retry import RetryExhausted, describe_exc, retry_request
from .base import Finding, ScanResult

log = logging.getLogger(__name__)


class HTTPSRedirectScanner:
    """Verify that http://<host> redirects to https://<host>.

    Mozilla Observatory checks this too, but it's worth surfacing on its
    own line: a misconfigured redirect (third-party hop, intermediate http,
    or no redirect at all) is a frequently-missed exposure.
    """

    name = "HTTP→HTTPS redirect"
    config_key = "https_redirect"

    async def scan(self, url: str, *, client: httpx.AsyncClient) -> ScanResult:
        host = urlparse(url).hostname
        if not host:
            return ScanResult(scanner=self.name, ok=False, error="Could not parse host from URL.", link=url)
        plain_url = f"http://{host}/"
        link = plain_url

        chain: list[str] = []
        try:
            resp = await retry_request(
                lambda: client.get(plain_url, follow_redirects=True, timeout=20.0),
                label=self.name, logger=log,
            )
        except RetryExhausted as e:
            # `httpx.ConnectError` is the umbrella for refused, DNS failure
            # (gaierror), and network-unreachable. Only ECONNREFUSED actually
            # means "HTTPS-only host" — treating DNS failure as A would falsely
            # green-grade a typo or expired domain. Walk the cause chain for
            # ConnectionRefusedError (Python's stdlib type for ECONNREFUSED);
            # fall back to a string match because httpx doesn't always preserve
            # the chain across the httpcore wrap.
            inner = e.last_exception
            is_refused = False
            if isinstance(inner, httpx.ConnectError):
                cause: BaseException | None = inner
                while cause is not None:
                    if isinstance(cause, ConnectionRefusedError):
                        is_refused = True
                        break
                    cause = cause.__cause__
                if not is_refused and "refused" in str(inner).lower():
                    is_refused = True
            if is_refused:
                return ScanResult(
                    scanner=self.name, ok=True, grade="A", score=90,
                    summary="Plain http:// is not served at all (HTTPS-only host).",
                    findings=[Finding(
                        severity="info",
                        title="No HTTP listener",
                        detail="Connection to http:// was refused. That's stricter than redirecting; nothing to fix.",
                    )],
                    link=link,
                )
            log.error("%s: %s", self.name, e)
            return ScanResult(scanner=self.name, ok=False, error=str(e), link=link)
        except httpx.HTTPError as e:
            return ScanResult(scanner=self.name, ok=False, error=describe_exc(e), link=link)

        # Build the redirect chain (request URLs walked through).
        for h in resp.history:
            chain.append(str(h.url))
        chain.append(str(resp.url))

        final = urlparse(str(resp.url))
        is_https = final.scheme == "https"
        same_host = (final.hostname or "").lower() == host.lower()

        # Did any intermediate hop stay on http? Bad - credentials could leak there.
        intermediate_http = any(urlparse(u).scheme == "http" for u in chain[1:])

        findings: list[Finding] = []
        if not is_https:
            grade, score = "F", 0
            summary = f"http:// did not redirect to HTTPS (final URL: {final.geturl()})."
            findings.append(Finding(
                severity="critical",
                title="No HTTPS redirect",
                detail=f"Plain HTTP request resolved to {final.geturl()} without a redirect to HTTPS.",
                recommendation="Configure a 301/308 redirect from http://<host>/ to https://<host>/.",
            ))
        elif not same_host:
            grade, score = "C", 65
            summary = f"http:// redirects to HTTPS but on a different host ({final.hostname})."
            findings.append(Finding(
                severity="medium",
                title="Redirect leaves the original host",
                detail=f"http://{host}/ → {final.geturl()}",
                recommendation="Redirect to HTTPS on the same host first, then to wherever else.",
            ))
        elif intermediate_http:
            grade, score = "B", 80
            summary = "Redirect chain visits HTTP before reaching HTTPS."
            findings.append(Finding(
                severity="low",
                title="Intermediate HTTP hop in redirect chain",
                detail="The redirect path was: " + " → ".join(chain),
                recommendation="Make the very first response a redirect to https://<host>/, with no http intermediate.",
            ))
        elif len(resp.history) == 0:
            # Shouldn't happen if we ended up on https, but defensive.
            grade, score = "B", 80
            summary = f"Reached HTTPS without an explicit redirect (final URL: {final.geturl()})."
        else:
            grade, score = "A+", 100
            summary = f"http:// redirects directly to https://{host}/ (chain length {len(chain) - 1})."
            findings.append(Finding(
                severity="info",
                title="Redirect chain",
                detail=" → ".join(chain),
            ))

        return ScanResult(
            scanner=self.name, ok=True, grade=grade, score=score,
            summary=summary, findings=findings, link=link,
        )
