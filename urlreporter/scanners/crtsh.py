from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlparse

import httpx

from ._retry import RetryExhausted, describe_exc, retry_request
from .base import Finding, ScanResult

log = logging.getLogger(__name__)

API = "https://crt.sh/?q={host}&output=json"
REPORT_URL = "https://crt.sh/?q={host}"

LOOKBACK_DAYS = 90


class CrtShScanner:
    """Certificate Transparency lookup via crt.sh.

    Surfaces every certificate that has ever been logged for the host. We
    grade based on how concentrated the issuing CAs are over the last 90
    days: a domain that suddenly has certs from many different CAs is a
    classic mis-issuance / compromise smell.
    """

    name = "crt.sh (Certificate Transparency)"
    config_key = "crtsh"

    async def scan(self, url: str, *, client: httpx.AsyncClient) -> ScanResult:
        host = urlparse(url).hostname
        if not host:
            return ScanResult(
                scanner=self.name,
                ok=False,
                error="Could not parse host from URL.",
                link="https://crt.sh/",
            )
        link = REPORT_URL.format(host=quote(host, safe=""))

        url_to_get = API.format(host=quote(host, safe=""))
        try:
            resp = await retry_request(
                lambda: client.get(url_to_get, timeout=30.0),
                label=self.name, logger=log,
                # crt.sh under load returns 404 for valid queries; retry it.
                treat_404_as_transient=True,
            )
            if resp.status_code >= 400:
                return ScanResult(scanner=self.name, ok=False,
                                  error=f"crt.sh returned HTTP {resp.status_code}.", link=link)
            certs = resp.json()
        except RetryExhausted as e:
            log.error("%s: %s", self.name, e)
            return ScanResult(scanner=self.name, ok=False, error=str(e), link=link)
        except (httpx.HTTPError, ValueError) as e:
            return ScanResult(scanner=self.name, ok=False, error=describe_exc(e), link=link)

        if not isinstance(certs, list):
            return ScanResult(scanner=self.name, ok=False, error="Unexpected response shape.", link=link)

        cutoff = datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)
        recent_certs = []
        for c in certs:
            ts = (c or {}).get("entry_timestamp") or (c or {}).get("not_before")
            if not ts:
                continue
            try:
                # crt.sh returns ISO-ish timestamps without timezone; assume UTC.
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
            except (TypeError, ValueError):
                continue
            if dt >= cutoff:
                recent_certs.append(c)

        issuers = sorted({(c.get("issuer_name") or "").strip() for c in recent_certs if c.get("issuer_name")})
        n_recent = len(recent_certs)
        n_total = len(certs)
        n_issuers = len(issuers)

        findings: list[Finding] = []
        if n_total == 0:
            findings.append(Finding(
                severity="medium",
                title="No certificates found in CT logs",
                detail="crt.sh has no record of any TLS certificate ever being issued for this host.",
                recommendation="If this is a real public site, that suggests the domain is brand-new or its certs aren't reaching public CT logs.",
            ))
            return ScanResult(
                scanner=self.name, ok=True, grade="D", score=40,
                summary="No certificates found in Certificate Transparency logs.",
                findings=findings, link=link,
            )

        # Grade by issuer concentration over the last 90 days.
        if n_recent == 0:
            grade, score = "C", 65
            summary = f"{n_total} historical cert(s) but none in the last {LOOKBACK_DAYS} days."
        elif n_issuers <= 2:
            grade, score = "A+", 100
            summary = f"{n_recent} cert(s) in last {LOOKBACK_DAYS}d from {n_issuers} CA(s)."
        elif n_issuers <= 4:
            grade, score = "A", 90
            summary = f"{n_recent} cert(s) in last {LOOKBACK_DAYS}d from {n_issuers} CA(s)."
        elif n_issuers <= 7:
            grade, score = "B", 75
            summary = f"{n_recent} cert(s) in last {LOOKBACK_DAYS}d from {n_issuers} different CAs."
            findings.append(Finding(
                severity="low",
                title=f"{n_issuers} different CAs issued certs in the last {LOOKBACK_DAYS} days",
                detail="A high CA churn can indicate uncoordinated cert provisioning.",
                recommendation="Pin issuance to a small set of CAs via CAA records.",
            ))
        else:
            grade, score = "C", 60
            summary = f"{n_recent} cert(s) in last {LOOKBACK_DAYS}d from {n_issuers} different CAs."
            findings.append(Finding(
                severity="medium",
                title=f"{n_issuers} different CAs issued certs in the last {LOOKBACK_DAYS} days",
                detail="A very high CA spread is unusual and warrants review.",
                recommendation="Audit the CAs in your CAA records and at your registrar.",
            ))

        if issuers:
            findings.append(Finding(
                severity="info",
                title=f"Issuing CAs (last {LOOKBACK_DAYS} days)",
                detail="; ".join(issuers[:10]) + ("…" if len(issuers) > 10 else ""),
                recommendation=None,
            ))

        return ScanResult(
            scanner=self.name, ok=True, grade=grade, score=score,
            summary=summary, findings=findings, link=link,
        )
