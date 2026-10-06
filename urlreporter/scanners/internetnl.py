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
    and clauses in NEXT_SCANNER.md). So no token can turn this into a scan,
    and the INTERNETNL_API_TOKEN setting that suggested one could was
    removed; the result points the reader at internet.nl's own test instead.
    """

    name = "internet.nl"
    config_key = "internetnl"

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
