from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from ._retry import RetryExhausted, describe_exc, retry_request
from .base import Finding, ScanResult

log = logging.getLogger(__name__)

# RFC 9116: the canonical location is /.well-known/security.txt; the
# pre-RFC location /security.txt is also recognized as a fallback.
WELLKNOWN_PATH = "/.well-known/security.txt"
LEGACY_PATH = "/security.txt"

# Field names defined by RFC 9116. We're case-insensitive when matching.
KNOWN_FIELDS = {
    "acknowledgments", "canonical", "contact", "encryption",
    "expires", "hiring", "policy", "preferred-languages",
}


def _parse(text: str) -> dict[str, list[str]]:
    """Parse a security.txt body into {field-name: [values]}.

    Field names are normalized to lowercase. Comments (`# …`) and blank
    lines are ignored. We tolerate CRLF or LF line endings and trim
    surrounding whitespace from values.
    """
    fields: dict[str, list[str]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        key = name.strip().lower()
        val = value.strip()
        if not key or not val:
            continue
        fields.setdefault(key, []).append(val)
    return fields


def _parse_iso_datetime(raw: str) -> datetime | None:
    """Parse the value of an `Expires:` field. RFC 9116 requires ISO 8601 in
    UTC with the explicit `Z` suffix, but we accept any parseable form."""
    s = raw.strip()
    s = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class SecurityTxtScanner:
    """RFC 9116 compliance check.

    A `security.txt` file at /.well-known/security.txt tells security
    researchers (and automated scanners) how to report vulnerabilities to
    the site. It is a low-effort, high-signal hygiene marker. We grade by
    whether the file exists at the canonical location, whether it parses,
    and how many of the recommended fields are present and current.
    """

    name = "security.txt (RFC 9116)"
    config_key = "security_txt"

    async def scan(self, url: str, *, client: httpx.AsyncClient) -> ScanResult:
        host = urlparse(url).hostname
        if not host:
            return ScanResult(
                scanner=self.name, ok=False,
                error="Could not parse host from URL.",
                link="https://www.rfc-editor.org/rfc/rfc9116",
            )
        # The user-facing link points at the canonical RFC URL; the result
        # page also surfaces the per-host candidate URL when found.
        link = f"https://{host}{WELLKNOWN_PATH}"

        # Probe both candidate locations concurrently. Preference order
        # (well-known wins if both 200) is preserved by walking the
        # gathered results in canonical-first order below. Firing both in
        # parallel mostly wins for the no-security.txt case (the common
        # one for a 70th-percentile site), where the previous sequential
        # loop paid two RTTs to learn there's no file; now it's one.
        async def _try_path(path: str) -> httpx.Response | str | None:
            """Returns the Response, an error-string for retry/HTTP failures,
            or None for the rare case retry_request itself produces no value."""
            candidate = f"https://{host}{path}"
            try:
                return await retry_request(
                    lambda: client.get(candidate, follow_redirects=True, timeout=15.0),
                    label=f"{self.name} GET {path}", logger=log,
                )
            except RetryExhausted as e:
                return str(e)
            except httpx.HTTPError as e:
                return describe_exc(e)

        results = await asyncio.gather(
            _try_path(WELLKNOWN_PATH), _try_path(LEGACY_PATH)
        )
        results_by_path = dict(zip((WELLKNOWN_PATH, LEGACY_PATH), results))

        body: str | None = None
        served_at: str | None = None
        last_error: str | None = None
        # Track whether we got at least one definitive HTTP response (200, 404,
        # 403, 410, or any other status). If both paths failed at the network
        # level (RetryExhausted, TLS error, etc.) we cannot conclude the file
        # is absent — only that we couldn't fetch. Without this distinction,
        # an unreachable host gets a misleading B-/70 "no security.txt" grade.
        got_definitive_response = False
        # Canonical-first: prefer /.well-known/security.txt, fall back to
        # /security.txt only if the canonical path didn't produce a usable file.
        for path in (WELLKNOWN_PATH, LEGACY_PATH):
            candidate = f"https://{host}{path}"
            r = results_by_path.get(path)
            if isinstance(r, str):
                # Network or retry error from the gathered call.
                last_error = r
                continue
            if r is None:
                continue
            got_definitive_response = True
            if r.status_code == 200:
                ctype = (r.headers.get("content-type") or "").lower()
                # text/plain is RFC-mandated, but be pragmatic: many sites
                # serve as text/html with a charset. Reject only obviously
                # wrong types like application/json or image/*.
                if ctype.startswith(("application/json", "image/", "video/", "application/octet-stream")):
                    last_error = f"Wrong content-type at {candidate}: {ctype}"
                    continue
                body = r.text
                served_at = candidate
                break
            elif r.status_code in (404, 403, 410):
                # Definitively not present at this path; move on without
                # treating it as an error.
                continue
            else:
                last_error = f"{candidate} returned HTTP {r.status_code}"
                continue

        findings: list[Finding] = []

        if body is None:
            if not got_definitive_response:
                # Both fetches failed at the transport layer. We cannot tell
                # whether security.txt is published or not — surface as scanner
                # failure rather than fabricating a "no security.txt" grade.
                log.error("%s: every candidate fetch failed: %s", self.name, last_error)
                return ScanResult(
                    scanner=self.name, ok=False,
                    error=f"Could not fetch security.txt from {host}: {last_error or 'all attempts failed'}",
                    link=link,
                )
            findings.append(Finding(
                severity="low",
                title="No security.txt file found",
                detail=(
                    f"Tried {WELLKNOWN_PATH} and {LEGACY_PATH}. "
                    "RFC 9116 expects a plain-text file at /.well-known/security.txt "
                    "describing how to report vulnerabilities. The file is recommended, "
                    "not required; absence is a hygiene gap, not a vulnerability."
                    + (f" Last error: {last_error}." if last_error else "")
                ),
                recommendation=(
                    "Publish a security.txt at /.well-known/security.txt with at minimum a "
                    "`Contact:` field (mailto: or https:) and an `Expires:` date in the future."
                ),
            ))
            return ScanResult(
                scanner=self.name, ok=True, grade="B-", score=70,
                summary="No security.txt published.",
                findings=findings, link=link,
            )

        fields = _parse(body)
        contacts = fields.get("contact", [])
        expires_raw = (fields.get("expires") or [None])[0]
        canonical = fields.get("canonical", [])
        policy = fields.get("policy", [])
        encryption = fields.get("encryption", [])
        ack = fields.get("acknowledgments", [])
        prefs = fields.get("preferred-languages", [])

        # Score
        score = 0
        if served_at == f"https://{host}{WELLKNOWN_PATH}":
            score += 30          # canonical location: full credit
        else:
            score += 10          # legacy /security.txt only: partial credit
        if contacts:
            score += 30
        # Expires field - required by RFC 9116; must be in the future.
        expires_dt = _parse_iso_datetime(expires_raw) if expires_raw else None
        if expires_dt:
            now = datetime.now(timezone.utc)
            if expires_dt > now:
                score += 25
            else:
                score += 5       # present but expired: weak credit
        if policy: score += 5
        if encryption: score += 4
        if ack: score += 3
        if prefs: score += 3

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

        # Findings
        if served_at != f"https://{host}{WELLKNOWN_PATH}":
            findings.append(Finding(
                severity="low",
                title="security.txt served from legacy /security.txt only",
                detail=f"Found at {served_at} but not at the RFC 9116 canonical location {WELLKNOWN_PATH}.",
                recommendation="Move the file (or add a copy) to /.well-known/security.txt to comply with RFC 9116.",
            ))
        if not contacts:
            findings.append(Finding(
                severity="high",
                title="security.txt is missing a Contact field",
                detail="`Contact:` is the only field required by RFC 9116. Without it the file is non-conforming.",
                recommendation="Add a `Contact: mailto:security@<your-domain>` (or a tracker URL) line.",
            ))
        else:
            findings.append(Finding(
                severity="info",
                title=f"Contact channel(s) advertised: {len(contacts)}",
                detail=" | ".join(contacts[:3]) + ("…" if len(contacts) > 3 else ""),
            ))
        if not expires_raw:
            findings.append(Finding(
                severity="medium",
                title="security.txt has no Expires field",
                detail="Required by RFC 9116. Helps researchers know whether the file is still trustworthy.",
                recommendation="Add an `Expires:` line in ISO-8601 UTC, e.g. `Expires: 2027-01-01T00:00:00Z`.",
            ))
        elif expires_dt is None:
            findings.append(Finding(
                severity="medium",
                title="security.txt Expires field is unparseable",
                detail=f"Got: {expires_raw!r}. RFC 9116 requires ISO 8601 (e.g. 2027-01-01T00:00:00Z).",
                recommendation="Replace with an ISO-8601 timestamp ending in Z (UTC).",
            ))
        else:
            now = datetime.now(timezone.utc)
            if expires_dt <= now:
                findings.append(Finding(
                    severity="high",
                    title="security.txt has expired",
                    detail=f"Expired on {expires_dt.isoformat()}; current time {now.isoformat()}.",
                    recommendation="Update the `Expires:` field to a future date and refresh the policy if needed.",
                ))
            elif (expires_dt - now).days < 30:
                findings.append(Finding(
                    severity="low",
                    title="security.txt expires within 30 days",
                    detail=f"Expires {expires_dt.isoformat()}.",
                    recommendation="Renew before expiry; RFC 9116 recommends rotating annually at minimum.",
                ))

        # Detect totally unknown field names (typos / non-RFC fields).
        unknown_fields = sorted(k for k in fields.keys() if k not in KNOWN_FIELDS)
        if unknown_fields:
            findings.append(Finding(
                severity="info",
                title=f"Unknown field(s) in security.txt: {', '.join(unknown_fields)}",
                detail="Not part of RFC 9116. Probably harmless but worth checking for typos.",
            ))

        bits = []
        bits.append("contact" if contacts else "no contact")
        if expires_dt:
            bits.append("expires " + expires_dt.date().isoformat())
        elif expires_raw:
            bits.append("expires unparseable")
        else:
            bits.append("no expires")
        if served_at and served_at != f"https://{host}{WELLKNOWN_PATH}":
            bits.append("legacy path")
        summary = "; ".join(bits)

        return ScanResult(
            scanner=self.name, ok=True, grade=grade, score=score,
            summary=summary, findings=findings,
            link=served_at or link,
        )
