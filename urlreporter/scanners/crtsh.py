from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from ._retry import RetryExhausted, describe_exc, retry_request
from .base import Finding, ScanResult

log = logging.getLogger(__name__)

CRTSH_API = "https://crt.sh/?q={host}&output=json"
CRTSH_REPORT = "https://crt.sh/?q={host}"
CERTSPOTTER_API = (
    # include_subdomains=true matches crt.sh's substring-search behavior:
    # `q=<apex>` on crt.sh returns subdomain certs (whose SANs contain the
    # apex), so for the failover to produce a comparable sample we have to
    # ask CertSpotter for subdomains too. Otherwise apex scans would be
    # graded on a much narrower cert set when CertSpotter is the source.
    "https://api.certspotter.com/v1/issuances?domain={host}"
    "&include_subdomains=true&expand=dns_names&expand=issuer"
)

LOOKBACK_DAYS = 90


class CrtShScanner:
    """Certificate Transparency lookup with crt.sh primary + CertSpotter fallback.

    Primary: crt.sh — broadest, most familiar UI for the same data.
    Fallback: CertSpotter (api.certspotter.com) — different operator (SSLmate),
    similar data, generous unauthenticated free tier. Used when crt.sh exhausts
    retries (5xx, network errors, etc.); rare for both to be down at the same
    time.

    Final fallback: when both sources fail, we degrade to a link-out result
    (ok=True, score=None) pointing at crt.sh's external page so the user can
    inspect manually. This keeps a third-party hiccup out of the report's
    'ERROR' bucket — same pattern InternetNL uses when no API token is set.
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
        link = CRTSH_REPORT.format(host=quote(host, safe=""))

        certs: list[dict[str, Any]] | None = None
        source = "crt.sh"
        try:
            certs = await _fetch_crtsh(host, client)
        except _SourceFailed as e:
            log.warning("crt.sh failed for %s, falling back to CertSpotter: %s", host, e)
            try:
                certs = await _fetch_certspotter(host, client)
                source = "CertSpotter"
            except _SourceFailed as e2:
                log.error("Both CT sources failed for %s: crt.sh=%s; certspotter=%s", host, e, e2)
                # Both upstreams down — degrade to link-out so the row doesn't
                # show as an ERROR (it's a third-party flake, not a problem
                # with the user's site).
                return ScanResult(
                    scanner=self.name,
                    ok=True,
                    grade=None,
                    score=None,
                    summary=(
                        "CT lookup unavailable: crt.sh and CertSpotter both unreachable. "
                        "Open the link to inspect Certificate Transparency manually."
                    ),
                    findings=[],
                    link=link,
                )

        return _grade(certs, link=link, source=source)


class _SourceFailed(Exception):
    """Raised internally when a single CT source exhausts retries / errors."""


async def _fetch_crtsh(host: str, client: httpx.AsyncClient) -> list[dict[str, Any]]:
    """Fetch normalized cert records from crt.sh. Raises _SourceFailed on any failure."""
    url_to_get = CRTSH_API.format(host=quote(host, safe=""))
    try:
        resp = await retry_request(
            lambda: client.get(url_to_get, timeout=30.0),
            label="crt.sh", logger=log,
            # crt.sh under load returns 404 for valid queries; retry it.
            treat_404_as_transient=True,
        )
    except RetryExhausted as e:
        raise _SourceFailed(str(e)) from e
    except httpx.HTTPError as e:
        raise _SourceFailed(describe_exc(e)) from e

    if resp.status_code >= 400:
        raise _SourceFailed(f"HTTP {resp.status_code}")

    try:
        data = resp.json()
    except ValueError as e:
        raise _SourceFailed(f"non-JSON response: {describe_exc(e)}") from e

    if not isinstance(data, list):
        raise _SourceFailed("unexpected response shape (not a JSON array)")

    return data


async def _fetch_certspotter(host: str, client: httpx.AsyncClient) -> list[dict[str, Any]]:
    """Fetch from CertSpotter and normalize to the crt.sh shape used by _grade.

    CertSpotter's response shape (subset):
        [
          {
            "id": "...",
            "dns_names": ["example.com"],
            "issuer": {"friendly_name": "Let's Encrypt R3", "name": "..."},
            "not_before": "2025-01-15T00:00:00Z",
            "not_after":  "2025-04-15T00:00:00Z"
          },
          ...
        ]

    crt.sh's shape (subset, what _grade reads):
        [
          {
            "entry_timestamp": "2025-01-15T00:00:00",  (for cutoff)
            "not_before":      "2025-01-15T00:00:00",  (fallback for cutoff)
            "issuer_name":     "C=US, O=Let's Encrypt, CN=R3",
          },
          ...
        ]
    """
    url_to_get = CERTSPOTTER_API.format(host=quote(host, safe=""))
    try:
        resp = await retry_request(
            lambda: client.get(url_to_get, timeout=30.0),
            label="CertSpotter", logger=log,
        )
    except RetryExhausted as e:
        raise _SourceFailed(str(e)) from e
    except httpx.HTTPError as e:
        raise _SourceFailed(describe_exc(e)) from e

    if resp.status_code >= 400:
        raise _SourceFailed(f"HTTP {resp.status_code}")

    try:
        data = resp.json()
    except ValueError as e:
        raise _SourceFailed(f"non-JSON response: {describe_exc(e)}") from e

    if not isinstance(data, list):
        raise _SourceFailed("unexpected response shape (not a JSON array)")

    # Normalize each issuance to the crt.sh field names _grade expects.
    normalized: list[dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        not_before = item.get("not_before")
        issuer = item.get("issuer") or {}
        issuer_name = (
            issuer.get("friendly_name") if isinstance(issuer, dict) else None
        ) or (issuer.get("name") if isinstance(issuer, dict) else None) or ""
        normalized.append({
            "entry_timestamp": not_before,
            "not_before": not_before,
            "issuer_name": issuer_name,
        })
    return normalized


def _grade(
    certs: list[dict[str, Any]],
    *,
    link: str,
    source: str,
) -> ScanResult:
    """Apply the same grading model regardless of which source produced the data.

    `source` is "crt.sh" or "CertSpotter"; surfaced in the summary for honesty
    about provenance. The full upstream-error detail lives in the per-run
    log; the report only needs to know which source was used.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)
    recent_certs = []
    for c in certs:
        ts = (c or {}).get("entry_timestamp") or (c or {}).get("not_before")
        if not ts:
            continue
        try:
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
            detail="No record of any TLS certificate ever being issued for this host.",
            recommendation="If this is a real public site, that suggests the domain is brand-new or its certs aren't reaching public CT logs.",
        ))
        return ScanResult(
            scanner=CrtShScanner.name, ok=True, grade="D", score=40,
            summary=_with_source("No certificates found in Certificate Transparency logs.", source),
            findings=findings, link=link,
        )

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
        scanner=CrtShScanner.name, ok=True, grade=grade, score=score,
        summary=_with_source(summary, source),
        findings=findings, link=link,
    )


def _with_source(summary: str, source: str) -> str:
    """Append a provenance suffix to the summary when CertSpotter served the data.

    The full retry trace from ``retry_request`` already lands in the per-run
    log (and includes the ``label="crt.sh"`` prefix). The report's summary cell
    just needs to record that the failover fired — keeping it concise avoids
    awkward duplication like "crt.sh unreachable: crt.sh: gave up after …".
    """
    if source == "crt.sh":
        return summary
    return f"{summary} (via CertSpotter — crt.sh unreachable)"
