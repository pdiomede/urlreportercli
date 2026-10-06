from __future__ import annotations

import logging
import re
import time
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

# crt.sh gets one quick retry, not the default three with 3/8/20s backoff:
# there is a fallback, and when crt.sh is down it is usually down for hours
# (502s on every request, its own web page included, all of 6 Oct 2026).
# The default schedule cost every scan ~45s before CertSpotter was asked.
# That retry is for quick failures only: a timed-out request is not retried
# (`retry_timeouts=False` below). On the same day crt.sh also accepted
# connections and then sent nothing for ~36s before a 502, and a retry of a
# stall like that cost a second 20s timeout, so one scan took 40s.
CRTSH_BACKOFFS: tuple[float, ...] = (3.0,)
CRTSH_TIMEOUT = 20.0

# After crt.sh fails, scans ask CertSpotter first for this long. Even one
# quick retry costs a scan 4s against a 502 and 20s against a stall, and
# crt.sh outages last hours, so every scan in the web app paid it again.
# Process memory, so it only helps the web app; a CLI run is a fresh process.
CRTSH_REST_SECONDS = 600.0
_crtsh_failed_at: float | None = None


def _crtsh_resting() -> bool:
    return (_crtsh_failed_at is not None
            and time.monotonic() - _crtsh_failed_at < CRTSH_REST_SECONDS)

_ORG_RE = re.compile(r'(?:^|,\s*)O=(?:"([^"]*)"|([^,]*))')


def _issuer_org(name: str) -> str:
    """The organisation behind an issuer name, so CAs are counted once each.

    crt.sh names the issuing *intermediate* ("C=US, O=Let's Encrypt, CN=R11").
    Let's Encrypt alone rotates R10, R11, E5 and E6, so counting full names
    made a Let's Encrypt-only site look like four CAs and cost it the A+.
    CertSpotter's friendly names are already per organisation and pass
    through unchanged.
    """
    m = _ORG_RE.search(name)
    if m:
        org = (m.group(1) if m.group(1) is not None else m.group(2)).strip()
        if org:
            return org
    return name.strip()


def _parse_ts(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


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

        global _crtsh_failed_at
        # crt.sh first, unless it failed recently. Either way the other source
        # is still asked when the first one fails, so resting crt.sh never
        # turns a CertSpotter hiccup into a link-out.
        resting = _crtsh_resting()
        sources = [("crt.sh", _fetch_crtsh), ("CertSpotter", _fetch_certspotter)]
        if resting:
            # CertSpotter goes first, but quickly: with its full retry policy a
            # 429 (its responses advertise a limit of 10, with an hour-long
            # Retry-After) or a stall held every scan in the rest window for
            # 31 to 151 seconds before crt.sh, possibly healthy, was asked.
            sources = [("CertSpotter", _fetch_certspotter_quickly), ("crt.sh", _fetch_crtsh)]
        errors: list[str] = []
        for source, fetch in sources:
            try:
                certs = await fetch(host, client)
            except _SourceFailed as e:
                if source == "crt.sh":
                    _crtsh_failed_at = time.monotonic()
                log.warning("%s failed for %s: %s", source, host, e)
                errors.append(f"{source}={e}")
                continue
            if source == "crt.sh":
                _crtsh_failed_at = None
            return _grade(certs, link=link, source=source, crtsh_skipped=resting)

        log.error("Both CT sources failed for %s: %s", host, "; ".join(errors))
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


class _SourceFailed(Exception):
    """Raised internally when a single CT source exhausts retries / errors."""


async def _fetch_crtsh(host: str, client: httpx.AsyncClient) -> list[dict[str, Any]]:
    """Fetch normalized cert records from crt.sh. Raises _SourceFailed on any failure."""
    url_to_get = CRTSH_API.format(host=quote(host, safe=""))
    try:
        resp = await retry_request(
            lambda: client.get(url_to_get, timeout=CRTSH_TIMEOUT),
            label="crt.sh", logger=log,
            backoffs=CRTSH_BACKOFFS,
            # crt.sh under load returns 404 for valid queries; retry it.
            treat_404_as_transient=True,
            retry_timeouts=False,
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


async def _fetch_certspotter_quickly(host: str, client: httpx.AsyncClient) -> list[dict[str, Any]]:
    """CertSpotter as the first source while crt.sh rests: one attempt, the
    same timeout as crt.sh, so a failure costs seconds before crt.sh is asked."""
    return await _fetch_certspotter(host, client, backoffs=(), timeout=CRTSH_TIMEOUT,
                                    retry_timeouts=False)


async def _fetch_certspotter(
    host: str,
    client: httpx.AsyncClient,
    *,
    backoffs: tuple[float, ...] | None = None,
    timeout: float = 30.0,
    retry_timeouts: bool = True,
) -> list[dict[str, Any]]:
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
            lambda: client.get(url_to_get, timeout=timeout),
            label="CertSpotter", logger=log,
            backoffs=backoffs, retry_timeouts=retry_timeouts,
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
            "not_after": item.get("not_after"),
            "issuer_name": issuer_name,
        })
    return normalized


def _grade(
    certs: list[dict[str, Any]],
    *,
    link: str,
    source: str,
    crtsh_skipped: bool = False,
) -> ScanResult:
    """Apply the same grading model regardless of which source produced the data.

    `source` is "crt.sh" or "CertSpotter"; surfaced in the summary for honesty
    about provenance. The full upstream-error detail lives in the per-run
    log; the report only needs to know which source was used.
    """
    # Grade on certificates issued in the last LOOKBACK_DAYS. When there are
    # none, grade on those still valid instead: a healthy site on a one-year
    # certificate issued more than 90 days ago used to get a C with no finding
    # to say why. Still-valid certificates are only the fallback because the
    # sample includes subdomains, and counting every long-lived one for a busy
    # domain (github.com: 5 CAs instead of 2) would change grades that were
    # right.
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=LOOKBACK_DAYS)
    recent_certs, valid_certs = [], []
    for c in certs:
        if not isinstance(c, dict):
            continue
        # Upstreams have been known to send a numeric timestamp; _parse_ts
        # skips those rather than taking the scanner down.
        issued = _parse_ts(c.get("entry_timestamp")) or _parse_ts(c.get("not_before"))
        expires = _parse_ts(c.get("not_after"))
        if issued and issued >= cutoff:
            recent_certs.append(c)
        if expires and expires >= now:
            valid_certs.append(c)
    if recent_certs:
        current_certs, basis = recent_certs, f"in last {LOOKBACK_DAYS}d"
    else:
        current_certs, basis = valid_certs, f"still valid (none issued in the last {LOOKBACK_DAYS}d)"

    issuers = sorted({
        _issuer_org(c.get("issuer_name") or "")
        for c in current_certs if (c.get("issuer_name") or "").strip()
    })
    n_current = len(current_certs)
    n_total = len(certs)
    n_issuers = len(issuers)

    findings: list[Finding] = []
    if n_total == 0:
        if source == "CertSpotter":
            # CertSpotter lists unexpired issuances only, so an empty answer
            # cannot say "never issued": the finding claimed exactly that for
            # hosts whose certificates had all expired.
            findings.append(Finding(
                severity="medium",
                title="No unexpired certificates found in CT logs",
                detail=(
                    "CertSpotter, which lists only certificates that have not expired, has none "
                    "for this host. Either none was ever issued or every one has expired; crt.sh, "
                    "which keeps expired ones, was unavailable to tell which."
                ),
                recommendation="If this is a real public site, check that it serves a current, publicly trusted certificate.",
            ))
            summary = "No unexpired certificates found in Certificate Transparency logs."
        else:
            findings.append(Finding(
                severity="medium",
                title="No certificates found in CT logs",
                detail="No record of any TLS certificate ever being issued for this host.",
                recommendation="If this is a real public site, that suggests the domain is brand-new or its certs aren't reaching public CT logs.",
            ))
            summary = "No certificates found in Certificate Transparency logs."
        return ScanResult(
            scanner=CrtShScanner.name, ok=True, grade="D", score=40,
            summary=_with_source(summary, source, crtsh_skipped=crtsh_skipped),
            findings=findings, link=link,
        )

    if n_current == 0:
        grade, score = "C", 59
        summary = f"{n_total} logged cert(s), all expired; none issued in the last {LOOKBACK_DAYS} days."
        findings.append(Finding(
            severity="medium",
            title="No currently valid certificate in CT logs",
            detail=(
                f"Every one of the {n_total} logged certificate(s) has expired, and none "
                f"was issued in the last {LOOKBACK_DAYS} days. Publicly trusted "
                "certificates have to be logged, so the certificate this site serves "
                "may not be publicly trusted, or may be issued for a different name."
            ),
            recommendation="Check the SSL Labs result for the certificate actually being served.",
        ))
    elif n_issuers <= 2:
        grade, score = "A+", 100
        summary = f"{n_current} cert(s) {basis} from {n_issuers} CA(s)."
    elif n_issuers <= 4:
        grade, score = "A", 89
        summary = f"{n_current} cert(s) {basis} from {n_issuers} CA(s)."
        findings.append(Finding(
            severity="low",
            title=f"{n_issuers} CAs have issued current certificates for this domain",
            detail=(
                "Each CA that issues for the domain is one more organisation that could "
                "mis-issue for it; two or fewer scores A+. Three or four is common when "
                "a CDN rotates between CAs."
            ),
            recommendation="Check that each is a CA you or your CDN use, and list exactly those in a CAA record.",
        ))
    elif n_issuers <= 7:
        grade, score = "B", 74
        summary = f"{n_current} cert(s) {basis} from {n_issuers} different CAs."
        findings.append(Finding(
            severity="low",
            title=f"{n_issuers} different CAs have issued current certificates",
            detail="A high CA churn can indicate uncoordinated cert provisioning.",
            recommendation="Pin issuance to a small set of CAs via CAA records.",
        ))
    else:
        grade, score = "C", 59
        summary = f"{n_current} cert(s) {basis} from {n_issuers} different CAs."
        findings.append(Finding(
            severity="medium",
            title=f"{n_issuers} different CAs have issued current certificates",
            detail="A very high CA spread is unusual and warrants review.",
            recommendation="Audit the CAs in your CAA records and at your registrar.",
        ))

    if issuers:
        findings.append(Finding(
            severity="info",
            title="Issuing CAs (current certificates)",
            detail="; ".join(issuers[:10]) + ("…" if len(issuers) > 10 else ""),
            recommendation=None,
        ))

    return ScanResult(
        scanner=CrtShScanner.name, ok=True, grade=grade, score=score,
        summary=_with_source(summary, source, crtsh_skipped=crtsh_skipped),
        findings=findings, link=link,
    )


def _with_source(summary: str, source: str, *, crtsh_skipped: bool = False) -> str:
    """Append a provenance suffix to the summary when CertSpotter served the data.

    The full retry trace from ``retry_request`` already lands in the per-run
    log (and includes the ``label="crt.sh"`` prefix). The report's summary cell
    just needs to record that the failover fired — keeping it concise avoids
    awkward duplication like "crt.sh unreachable: crt.sh: gave up after …".
    """
    if source == "crt.sh":
        return summary
    if crtsh_skipped:
        return f"{summary} (via CertSpotter — crt.sh skipped after a recent failure)"
    return f"{summary} (via CertSpotter — crt.sh unreachable)"
