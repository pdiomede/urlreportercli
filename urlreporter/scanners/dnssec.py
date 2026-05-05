from __future__ import annotations

import logging
from urllib.parse import urlparse

import httpx

from ._retry import RetryExhausted, describe_exc, retry_request
from .base import Finding, ScanResult

log = logging.getLogger(__name__)

DOH_URL = "https://cloudflare-dns.com/dns-query"
REPORT_URL = "https://dnssec-analyzer.verisignlabs.com/{host}"


class DNSSECScanner:
    """DNSSEC validation via Cloudflare DNS-over-HTTPS.

    Cloudflare returns AD=true when the response was DNSSEC-validated all
    the way to the root. The absence of the AD flag (with CD not set) means
    the domain either lacks DNSSEC or has a broken chain.
    """

    name = "DNSSEC"
    config_key = "dnssec"

    async def scan(self, url: str, *, client: httpx.AsyncClient) -> ScanResult:
        host = urlparse(url).hostname
        if not host:
            return ScanResult(
                scanner=self.name, ok=False,
                error="Could not parse host from URL.",
                link=DOH_URL,
            )
        link = REPORT_URL.format(host=host)

        try:
            resp = await retry_request(
                lambda: client.get(
                    DOH_URL,
                    params={"name": host, "type": "SOA", "do": "1"},
                    headers={"Accept": "application/dns-json"},
                    timeout=15.0,
                ),
                label=self.name, logger=log,
            )
            if resp.status_code >= 400:
                return ScanResult(scanner=self.name, ok=False,
                                  error=f"DoH returned HTTP {resp.status_code}.", link=link)
            data = resp.json()
        except RetryExhausted as e:
            log.error("%s: %s", self.name, e)
            return ScanResult(scanner=self.name, ok=False, error=str(e), link=link)
        except (httpx.HTTPError, ValueError) as e:
            return ScanResult(scanner=self.name, ok=False, error=describe_exc(e), link=link)

        ad = bool(data.get("AD"))
        rcode = data.get("Status", 0)

        if rcode != 0:
            # Translate the RCODE into a useful human message and recommendation
            # rather than always blaming DNSSEC.
            rcode_meta = {
                1: ("FORMERR (1)", "The query was malformed; usually a client bug, not a domain issue."),
                2: ("SERVFAIL (2)", "Often a broken DNSSEC chain. Check DS records at the registrar; mismatched DS to DNSKEY causes SERVFAIL."),
                3: ("NXDOMAIN (3)", "The domain does not exist. Check spelling and registration status; DNSSEC is not the issue here."),
                4: ("NOTIMP (4)", "The resolver does not implement this query type. Try a different DoH endpoint."),
                5: ("REFUSED (5)", "The resolver refused to answer (rate limit, ACL, or policy). Retry later or with a different resolver."),
            }
            label, advice = rcode_meta.get(
                rcode,
                (f"RCODE {rcode}", "Non-zero DNS RCODE returned; see RFC 1035 / 6895 for the meaning."),
            )
            return ScanResult(
                scanner=self.name, ok=True, grade="F", score=0,
                summary=f"DNS resolution returned {label}.",
                findings=[Finding(
                    severity="high",
                    title=f"DNS resolution failed: {label}",
                    detail=f"The resolver returned RCODE {rcode}.",
                    recommendation=advice,
                )],
                link=link,
            )

        if ad:
            return ScanResult(
                scanner=self.name, ok=True, grade="A+", score=100,
                summary="DNSSEC validates (AD flag set by Cloudflare resolver).",
                findings=[], link=link,
            )

        return ScanResult(
            scanner=self.name, ok=True, grade="D", score=40,
            summary="No DNSSEC: response was not authenticated (AD flag clear).",
            findings=[Finding(
                severity="medium",
                title="DNSSEC not enabled",
                detail="The zone is not signed, or the chain to the root cannot be validated.",
                recommendation="Enable DNSSEC at your registrar and DNS provider; publish DS records to the parent zone.",
            )],
            link=link,
        )
