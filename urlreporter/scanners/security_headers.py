from __future__ import annotations

import asyncio
import logging
import re
from urllib.parse import quote, urlparse

import httpx

from ..grading import letter_to_score, score_to_letter
from ._retry import RetryExhausted, describe_exc, retry_request
from .base import Finding, ScanResult

log = logging.getLogger(__name__)

_GRADE_RE = re.compile(r"^[A-F][+\-]?$")

API = "https://securityheaders.com/"
REPORT_URL = "https://securityheaders.com/?q={url}&followRedirects=on"

# Headers we expect on any modern site, with severity if missing.
EXPECTED_HEADERS: dict[str, tuple[str, str]] = {
    "strict-transport-security": (
        "high",
        "Add Strict-Transport-Security: max-age=31536000; includeSubDomains.",
    ),
    "content-security-policy": (
        "high",
        "Add a Content-Security-Policy that restricts script/style sources.",
    ),
    "x-content-type-options": (
        "medium",
        "Add X-Content-Type-Options: nosniff.",
    ),
    "x-frame-options": (
        "medium",
        "Add X-Frame-Options: DENY (or use CSP frame-ancestors 'none').",
    ),
    "referrer-policy": (
        "low",
        "Add Referrer-Policy: strict-origin-when-cross-origin.",
    ),
    "permissions-policy": (
        "low",
        "Add a Permissions-Policy header restricting unused browser features.",
    ),
}

# Penalty (out of 100) for each missing header by severity. Calibrated so that
# a site missing every modern header lands in F territory and one with all
# headers present scores A+.
_SEVERITY_PENALTY: dict[str, int] = {"high": 25, "medium": 15, "low": 5}


class SecurityHeadersScanner:
    name = "securityheaders.com"
    config_key = "security_headers"

    async def scan(self, url: str, *, client: httpx.AsyncClient) -> ScanResult:
        link = REPORT_URL.format(url=quote(url, safe=""))

        # Two independent fetches: the X-Grade probe at securityheaders.com
        # and a direct fetch of the target's own response (to surface missing
        # security headers as findings, and as a fallback when the X-Grade is
        # gated). The direct fetch doesn't depend on the grade fetch's result,
        # so fire them concurrently. Wall time becomes max(call) instead of
        # sum(call) — saves roughly half the scanner's time on a healthy run.
        async def _fetch_grade() -> tuple[str | None, str | None]:
            """Returns (grade, error_message). At most one is set."""
            try:
                resp = await retry_request(
                    lambda: client.get(
                        API,
                        params={"q": url, "hide": "on", "followRedirects": "on"},
                        headers={"Accept": "*/*"},
                    ),
                    label=f"{self.name} grade", logger=log,
                )
            except RetryExhausted as e:
                log.error("%s: %s", self.name, e)
                return None, str(e)
            except httpx.HTTPError as e:
                return None, describe_exc(e)
            raw = resp.headers.get("X-Grade") or resp.headers.get("x-grade")
            if raw is not None:
                normalized = raw.strip().upper()
                if _GRADE_RE.match(normalized):
                    return normalized, None
                return None, raw.strip()
            # X-Grade header gone — parse grade from HTML body.
            m = re.search(
                r'class="score".*?<span[^>]*>([A-F][+\-]?)</span>',
                resp.text,
                re.DOTALL,
            )
            if m and _GRADE_RE.match(m.group(1).upper()):
                return m.group(1).upper(), None
            return None, "No X-Grade header in response."

        async def _fetch_target() -> httpx.Response | None:
            try:
                return await retry_request(
                    lambda: client.get(url, follow_redirects=True),
                    label=f"{self.name} direct fetch", logger=log,
                )
            except (RetryExhausted, httpx.HTTPError) as e:
                log.warning("%s: direct fetch failed: %s", self.name, describe_exc(e))
                return None

        (grade, grade_error), target_resp = await asyncio.gather(
            _fetch_grade(), _fetch_target()
        )

        findings: list[Finding] = []
        synth_score: int | None = None
        if target_resp is not None:
            present = {k.lower(): v for k, v in target_resp.headers.items()}
            scheme = urlparse(str(target_resp.url)).scheme
            synth_score = 100
            for header, (severity, recommendation) in EXPECTED_HEADERS.items():
                if header == "strict-transport-security" and scheme != "https":
                    continue
                if header not in present:
                    synth_score -= _SEVERITY_PENALTY.get(severity, 10)
                    findings.append(
                        Finding(
                            severity=severity,  # type: ignore[arg-type]
                            title=f"Missing header: {header}",
                            detail="Header is not present on the response.",
                            recommendation=recommendation,
                        )
                    )
            synth_score = max(0, synth_score)

        # Prefer securityheaders.com's grade when available; fall back to the
        # locally-computed grade when it isn't (rate-limited, bot-challenged,
        # or X-Grade header dropped without an HTML fallback we can parse).
        if grade is not None:
            score = letter_to_score(grade)
            summary = f"Headers grade {grade}"
            ok = True
            error: str | None = None
        elif synth_score is not None:
            grade = score_to_letter(synth_score)
            score = synth_score
            summary = (
                f"Headers grade {grade} ({synth_score}/100) — graded locally; "
                "securityheaders.com unreachable."
            )
            ok = True
            error = None
        else:
            score = None
            summary = "Headers grade unavailable"
            ok = False
            error = grade_error

        return ScanResult(
            scanner=self.name,
            ok=ok,
            grade=grade,
            score=score,
            summary=summary,
            findings=findings,
            link=link,
            error=error,
        )
