from __future__ import annotations

import logging
from urllib.parse import urlparse

import httpx

from .base import Finding, ScanResult

log = logging.getLogger(__name__)

REPORT_URL = "https://internet.nl/site/{host}/"


class InternetNLScanner:
    """Always a link-out: internet.nl has no API this tool may use.

    Its only API is a batch API whose terms forbid this use three ways:
    single-domain requests are not allowed, it may not back a public
    third-party front-end, and fair use caps it at 2 batches a week (research
    and clauses in NEXT_SCANNER.md). So no token can turn this into a scan;
    the result points the reader at internet.nl's own test instead.
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

        # A configured token is ignored, and said so: an operator who set one
        # must not assume it is in use. Visitors never set it, so the plain
        # summary doesn't mention it. It used to say "no INTERNETNL_API_TOKEN
        # configured (batch API requires registration)", which told every web
        # visitor about a server setting and implied registering would help.
        if self.api_token:
            log.warning(
                "%s: INTERNETNL_API_TOKEN is set but ignored: internet.nl's batch API "
                "terms rule out single-site scans for a public front-end "
                "(see NEXT_SCANNER.md); using the manual link-out",
                self.name,
            )
            summary = (
                "Link-out: INTERNETNL_API_TOKEN is set but not used, because "
                "internet.nl's batch API terms rule out single-site scans."
            )
        else:
            summary = (
                "Link-out: internet.nl offers no API for single-site scans. "
                "Open the link to run its test."
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
