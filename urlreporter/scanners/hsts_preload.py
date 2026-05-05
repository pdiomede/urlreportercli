from __future__ import annotations

import logging
from urllib.parse import urlparse

import httpx

from ._retry import RetryExhausted, describe_exc, retry_request
from .base import Finding, ScanResult

log = logging.getLogger(__name__)

API = "https://hstspreload.org/api/v2/status"
REPORT_URL = "https://hstspreload.org/?domain={host}"


class HSTSPreloadScanner:
    name = "HSTS Preload"
    config_key = "hsts_preload"

    async def scan(self, url: str, *, client: httpx.AsyncClient) -> ScanResult:
        host = urlparse(url).hostname
        if not host:
            return ScanResult(
                scanner=self.name,
                ok=False,
                error="Could not parse host from URL.",
                link="https://hstspreload.org/",
            )
        link = REPORT_URL.format(host=host)

        try:
            resp = await retry_request(
                lambda: client.get(API, params={"domain": host}),
                label=self.name, logger=log,
            )
            if resp.status_code >= 400:
                return ScanResult(scanner=self.name, ok=False,
                                  error=f"hstspreload.org returned HTTP {resp.status_code}.", link=link)
            data = resp.json()
        except RetryExhausted as e:
            log.error("%s: %s", self.name, e)
            return ScanResult(scanner=self.name, ok=False, error=str(e), link=link)
        except (httpx.HTTPError, ValueError) as e:
            return ScanResult(scanner=self.name, ok=False, error=describe_exc(e), link=link)

        status = (data.get("status") or "").lower()

        if status == "preloaded":
            return ScanResult(
                scanner=self.name,
                ok=True,
                grade="A+",
                score=100,
                summary="Domain is on the Chrome HSTS preload list.",
                findings=[],
                link=link,
            )
        if status == "pending":
            return ScanResult(
                scanner=self.name,
                ok=True,
                grade="A",
                score=90,
                summary="Domain is pending inclusion on the HSTS preload list.",
                findings=[
                    Finding(
                        severity="low",
                        title="HSTS preload pending",
                        detail="Submission has been accepted but is not yet shipped in Chrome.",
                        recommendation="Wait for the next Chrome release; nothing to do.",
                    )
                ],
                link=link,
            )

        # Unknown / not preloaded. Preloading is opt-in and most major sites
        # are not preloaded; treat absence as a hardening recommendation, not
        # a failure.
        return ScanResult(
            scanner=self.name,
            ok=True,
            grade="B+",
            score=80,
            summary="Domain is NOT on the HSTS preload list.",
            findings=[
                Finding(
                    severity="low",
                    title="Not HSTS-preloaded",
                    detail="The domain has not been submitted to or accepted by hstspreload.org. Preloading is opt-in; absence is a hardening opportunity, not a vulnerability.",
                    recommendation="Serve Strict-Transport-Security with includeSubDomains; preload, then submit at https://hstspreload.org/.",
                )
            ],
            link=link,
        )
