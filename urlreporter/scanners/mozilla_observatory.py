from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

import httpx

from ..grading import fit_score_to_letter, letter_to_score
from ._retry import RetryExhausted, describe_exc, retry_request
from .base import Finding, ScanResult

API = "https://observatory-api.mdn.mozilla.net/api/v2/scan"
REPORT_URL = "https://developer.mozilla.org/en-US/observatory/analyze?host={host}"

log = logging.getLogger(__name__)


class MozillaObservatoryScanner:
    name = "Mozilla Observatory"
    config_key = "mozilla_observatory"

    async def scan(self, url: str, *, client: httpx.AsyncClient) -> ScanResult:
        host = urlparse(url).hostname
        if not host:
            return ScanResult(
                scanner=self.name,
                ok=False,
                error="Could not parse host from URL.",
                link=REPORT_URL.format(host=urlparse(url).netloc or url),
            )
        link = REPORT_URL.format(host=host)

        try:
            resp = await retry_request(
                lambda: client.post(API, params={"host": host}),
                label=f"{self.name} POST scan", logger=log,
            )
            if resp.status_code >= 400:
                return ScanResult(scanner=self.name, ok=False,
                                  error=_describe_refusal(resp), link=link)
            scan = resp.json()
        except RetryExhausted as e:
            log.error("%s: %s", self.name, e)
            return ScanResult(scanner=self.name, ok=False, error=str(e), link=link)
        except (httpx.HTTPError, ValueError) as e:
            return ScanResult(scanner=self.name, ok=False, error=describe_exc(e), link=link)

        score = scan.get("score")
        grade = scan.get("grade")
        scan_id = scan.get("id")

        findings: list[Finding] = []
        if scan_id:
            try:
                tests_resp = await retry_request(
                    lambda: client.get(f"{API}/{scan_id}/tests"),
                    label=f"{self.name} GET tests", logger=log,
                )
                if tests_resp.status_code == 200:
                    tests = tests_resp.json()
                    if isinstance(tests, dict):
                        iterable = list(tests.values())
                    elif isinstance(tests, list):
                        iterable = tests
                    else:
                        # Some responses are `null` or a scalar; nothing to do.
                        iterable = []
                    for test in iterable:
                        if not isinstance(test, dict):
                            continue
                        if test.get("pass") is False:
                            modifier = test.get("score_modifier") or 0
                            severity = "high" if modifier <= -20 else ("medium" if modifier <= -10 else "low")
                            findings.append(
                                Finding(
                                    severity=severity,
                                    title=test.get("name") or test.get("title") or "Failed check",
                                    detail=test.get("score_description") or "",
                                    recommendation=_recommendation_for(test.get("name", "")),
                                )
                            )
            except (httpx.HTTPError, ValueError) as e:
                log.warning("%s: tests endpoint failed: %s", self.name, describe_exc(e))

        normalized_score = score
        if normalized_score is None and grade:
            normalized_score = letter_to_score(grade)
        if isinstance(normalized_score, (int, float)):
            normalized_score = max(0, min(100, int(normalized_score)))
            if grade:
                # Mozilla's letter is what the reader sees on Mozilla's site,
                # but its number runs on Mozilla's scale: their 95 beside an
                # "A" would read back as our A+.
                normalized_score = fit_score_to_letter(normalized_score, grade)

        # Mozilla's own number goes in the summary, labelled as Mozilla's: it
        # runs past 100 and is clamped into the letter's band above, so
        # printing it bare beside the row's score read as two scores for one
        # result ("A (89/100) - grade A (90/100)").
        if grade is None:
            summary = "Mozilla Observatory result"
        elif score is None or score == normalized_score:
            summary = f"HTTP best-practice grade {grade}" + (f" ({score}/100)" if score is not None else "")
        else:
            summary = (
                f"HTTP best-practice grade {grade} "
                f"(Mozilla's score {score}, counted as {normalized_score} here)"
            )

        return ScanResult(
            scanner=self.name,
            ok=True,
            grade=grade,
            score=normalized_score,
            summary=summary,
            findings=findings,
            link=link,
        )


# Upstream text lands verbatim in the report, so cap it.
_MAX_MESSAGE_LEN = 200
_CODE_RE = re.compile(r"[a-z0-9-]{1,40}")


def _describe_refusal(resp: httpx.Response) -> str:
    """Turn an Observatory error response into a ScanResult error string.

    Observatory answers a site it can't scan with `{"error": <code>,
    "message": <text>}` — `site-down`, `unexpected-status-code`,
    `invalid-hostname-lookup` and friends. Those almost always describe the
    target as seen from Mozilla's servers, which is the one thing the reader
    needs; the bare status code told them nothing. The code goes in a fixed
    `(code)` slot because `report.explain_error` matches on it.
    """
    base = f"Observatory returned HTTP {resp.status_code}"
    try:
        body = resp.json()
    except ValueError:
        return f"{base}."
    if not isinstance(body, dict):
        return f"{base}."
    code = body.get("error")
    message = body.get("message")
    if isinstance(code, str) and _CODE_RE.fullmatch(code):
        base += f" ({code})"
    if isinstance(message, str) and message.strip():
        message = " ".join(message.split())
        if len(message) > _MAX_MESSAGE_LEN:
            message = message[:_MAX_MESSAGE_LEN - 1].rstrip() + "…"
        return f"{base}: {message}"
    return f"{base}."


def _recommendation_for(test_name: str) -> str | None:
    table = {
        "content-security-policy": "Add a strict Content-Security-Policy header.",
        "cookies": "Mark cookies Secure, HttpOnly, and SameSite=Lax/Strict.",
        "cross-origin-resource-sharing": "Tighten Access-Control-Allow-Origin to specific origins, not *.",
        "redirection": "Redirect HTTP to HTTPS on the same host before any other redirects.",
        "referrer-policy": "Set Referrer-Policy: no-referrer or strict-origin-when-cross-origin.",
        "strict-transport-security": "Add Strict-Transport-Security with max-age >= 15768000 and includeSubDomains.",
        "subresource-integrity": "Add integrity= and crossorigin= attributes to external <script>/<link> tags.",
        "x-content-type-options": "Add X-Content-Type-Options: nosniff.",
        "x-frame-options": "Add X-Frame-Options: DENY (or use CSP frame-ancestors).",
    }
    return table.get(test_name.lower()) if test_name else None
