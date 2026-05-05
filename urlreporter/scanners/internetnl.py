from __future__ import annotations

import logging
from urllib.parse import urlparse

import httpx

from .base import Finding, ScanResult

log = logging.getLogger(__name__)

REPORT_URL = "https://internet.nl/site/{host}/"


class InternetNLScanner:
    """internet.nl exposes a batch API that requires registration; there is no free
    single-scan API. Without a token we emit a link-out result so the user can run
    the test manually. With a token, future versions can call the batch API.
    """

    name = "internet.nl"
    config_key = "internetnl"

    def __init__(self, *, api_token: str | None = None) -> None:
        self.api_token = api_token

    async def scan(self, url: str, *, client: httpx.AsyncClient) -> ScanResult:
        host = urlparse(url).hostname
        if not host:
            return ScanResult(
                scanner=self.name,
                ok=False,
                error="Could not parse host from URL.",
                link="https://internet.nl/",
            )
        link = REPORT_URL.format(host=host)

        # Batch-API integration is not implemented yet. Whether or not a token
        # is configured, we emit the same link-out result so the user gets
        # something usable instead of a hard error. If a token IS configured,
        # we log a warning so the operator knows it's currently ignored.
        if self.api_token:
            log.warning(
                "%s: INTERNETNL_API_TOKEN is set but the batch-API integration is not yet implemented; falling back to manual link-out",
                self.name,
            )
            summary = (
                "Link-out: INTERNETNL_API_TOKEN configured but batch-API integration "
                "is not implemented yet (using manual check)."
            )
        else:
            summary = (
                "Link-out: no INTERNETNL_API_TOKEN configured "
                "(internet.nl batch API requires registration)."
            )

        return ScanResult(
            scanner=self.name,
            ok=True,
            grade=None,
            score=None,
            summary=summary,
            findings=[
                Finding(
                    severity="info",
                    title="internet.nl manual check",
                    detail="No public single-scan API is available; run the test in your browser to get DNSSEC, IPv6, TLS, and mail-security results.",
                    recommendation=f"Open {link} and review the results.",
                )
            ],
            link=link,
        )
