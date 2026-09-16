from __future__ import annotations

import asyncio
import logging
from urllib.parse import urlparse

import httpx

from ..grading import letter_to_score
from ._retry import describe_exc
from .base import Finding, ScanResult

log = logging.getLogger(__name__)

API = "https://api.ssllabs.com/api/v3/analyze"
REPORT_URL = "https://www.ssllabs.com/ssltest/analyze.html?d={host}"

# Transient HTTP statuses returned by SSL Labs / its CDN under load.
TRANSIENT_STATUSES = {429, 500, 502, 503, 504, 521, 522, 523, 524, 525, 526, 529}
MAX_TRANSIENT_RETRIES = 3
TRANSIENT_BACKOFFS = [5, 15, 30]  # seconds; len == MAX_TRANSIENT_RETRIES


class SSLLabsScanner:
    name = "SSL Labs"
    config_key = "ssl_labs"

    def __init__(self, *, use_cache: bool = True, timeout_seconds: int = 180) -> None:
        self.use_cache = use_cache
        self.timeout_seconds = timeout_seconds

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
        params = {"host": host, "all": "done"}
        if self.use_cache:
            params["fromCache"] = "on"
            params["maxAge"] = "24"

        deadline = asyncio.get_running_loop().time() + self.timeout_seconds
        last_data: dict | None = None
        transient_retries = 0
        poll_count = 0
        try:
            while True:
                try:
                    resp = await client.get(API, params=params)
                    resp.raise_for_status()
                except httpx.HTTPStatusError as e:
                    code = e.response.status_code
                    if code in TRANSIENT_STATUSES and transient_retries < MAX_TRANSIENT_RETRIES:
                        delay = TRANSIENT_BACKOFFS[transient_retries]
                        transient_retries += 1
                        await asyncio.sleep(delay)
                        continue
                    return ScanResult(
                        scanner=self.name,
                        ok=False,
                        error=f"SSL Labs API returned HTTP {code}.",
                        link=link,
                    )
                except httpx.RequestError as e:
                    if transient_retries < MAX_TRANSIENT_RETRIES:
                        delay = TRANSIENT_BACKOFFS[transient_retries]
                        transient_retries += 1
                        await asyncio.sleep(delay)
                        continue
                    return ScanResult(
                        scanner=self.name,
                        ok=False,
                        error=f"Network error talking to SSL Labs: {describe_exc(e)}",
                        link=link,
                    )

                # Success path: reset transient retry counter for the next poll.
                transient_retries = 0
                data = resp.json()
                last_data = data
                status = data.get("status")
                if status == "READY":
                    break
                if status == "ERROR":
                    msg = data.get("statusMessage") or "SSL Labs reported ERROR"
                    return ScanResult(scanner=self.name, ok=False, error=msg, link=link)
                if asyncio.get_running_loop().time() > deadline:
                    # SSL Labs is still polling (status IN_PROGRESS / DNS) when
                    # the deadline expired. The target site is fine — SSL Labs
                    # would have returned `status=ERROR` if it found a problem.
                    # We just ran out of time. Degrade to a link-out result
                    # (ok=True, score=None) so the row drops out of the red
                    # ERROR bucket and into the same "no public API" bucket
                    # InternetNL and the crt.sh double-fail use. Already
                    # excluded from the weighted average via aggregate_score's
                    # `score is not None` filter; the user clicks the link to
                    # watch the assessment finish on ssllabs.com directly.
                    return ScanResult(
                        scanner=self.name,
                        ok=True,
                        grade=None,
                        score=None,
                        summary=(
                            f"Assessment still running after {self.timeout_seconds}s. "
                            "First-time SSL Labs scans take 1-3 minutes; cached "
                            "scans return in seconds. Open the link to watch live "
                            "progress on ssllabs.com."
                        ),
                        findings=[],
                        link=link,
                    )
                # Adaptive polling: 3s cadence for the first 4 polls catches
                # cache hits and DNS-only stalls quickly; beyond that ramp to
                # 10s so genuine cache-miss assessments don't pound the API.
                poll_count += 1
                await asyncio.sleep(3 if poll_count <= 4 else 10)
        except httpx.HTTPError as e:
            return ScanResult(scanner=self.name, ok=False, error=describe_exc(e), link=link)

        endpoints = (last_data or {}).get("endpoints") or []
        if not endpoints:
            return ScanResult(
                scanner=self.name,
                ok=False,
                error="SSL Labs returned no endpoints.",
                link=link,
            )

        # Pick the worst grade across endpoints (more conservative).
        grades = [ep.get("grade") for ep in endpoints if ep.get("grade")]
        if not grades:
            return ScanResult(
                scanner=self.name,
                ok=False,
                error="SSL Labs returned no grades.",
                link=link,
            )
        # Rank only the grades we can actually interpret. The old key was
        # `letter_to_score(g) or 0`, which collapsed two different things into
        # zero: a genuine F, and a grade absent from LETTER_TO_SCORE. An
        # unrecognised grade therefore sorted as the *worst* endpoint, won the
        # `min`, and was handed to `letter_to_score` again for the score —
        # returning None. One odd endpoint could both hijack the verdict and
        # silently drop this weight-2.0 scanner out of the overall average
        # (aggregate_score skips `score is None`), with no error shown anywhere.
        ranked = [(g, letter_to_score(g)) for g in grades]
        known = [(g, sc) for g, sc in ranked if sc is not None]
        unknown = sorted({g for g, sc in ranked if sc is None})

        if not known:
            # Nothing interpretable. Degrade to a link-out rather than invent a
            # number — the same shape the deadline-expiry path above uses, and
            # honest about the fact that the assessment itself succeeded.
            return ScanResult(
                scanner=self.name,
                ok=True,
                grade=None,
                score=None,
                summary=(
                    f"SSL Labs returned {'a grade' if len(unknown) == 1 else 'grades'} "
                    f"this build does not recognise ({', '.join(unknown)}). "
                    "Open the link for the full assessment."
                ),
                findings=[Finding(
                    severity="info",
                    title=f"Unrecognised SSL Labs grade: {', '.join(unknown)}",
                    detail=(
                        "The endpoint(s) were assessed successfully, but the grade is not "
                        "one this build knows how to score, so it is excluded from the "
                        "overall average rather than guessed at."
                    ),
                    recommendation="Open the SSL Labs report and read the grade directly.",
                )],
                link=link,
            )

        worst, score = min(known, key=lambda pair: pair[1])

        findings: list[Finding] = []
        if unknown:
            findings.append(Finding(
                severity="info",
                title=f"Unrecognised SSL Labs grade on {len(unknown)} endpoint(s): {', '.join(unknown)}",
                detail=(
                    f"Graded on the {len(known)} endpoint(s) with a known grade; the "
                    "unrecognised one(s) are neither counted nor assumed to be bad."
                ),
                recommendation="Open the SSL Labs report to see those endpoints in full.",
            ))
        for ep in endpoints:
            ip = ep.get("ipAddress", "?")
            grade = ep.get("grade")
            details = ep.get("details") or {}
            if grade and letter_to_score(grade) is not None and letter_to_score(grade) < 80:
                findings.append(
                    Finding(
                        severity="high" if letter_to_score(grade) < 60 else "medium",
                        title=f"TLS endpoint graded {grade} ({ip})",
                        detail=ep.get("statusMessage", ""),
                        recommendation="Review TLS protocol versions, cipher suites, and certificate chain on this endpoint.",
                    )
                )
            for protocol in details.get("protocols") or []:
                pname = f"{protocol.get('name','?')} {protocol.get('version','?')}"
                if pname.startswith("TLS 1.0") or pname.startswith("TLS 1.1") or pname.startswith("SSL"):
                    findings.append(
                        Finding(
                            severity="high",
                            title=f"Legacy protocol enabled: {pname}",
                            detail=f"Endpoint {ip} accepts {pname}.",
                            recommendation="Disable SSL 3, TLS 1.0, and TLS 1.1 - only TLS 1.2+ should be enabled.",
                        )
                    )
            cert_chains = details.get("certChains") or []
            for chain in cert_chains:
                for issue in chain.get("issues") or []:
                    if isinstance(issue, dict) and issue.get("severity"):
                        findings.append(
                            Finding(
                                severity="medium",
                                title=f"Certificate chain issue: {issue.get('summary','')}",
                                detail=issue.get("description", ""),
                                recommendation="Fix the certificate chain (intermediates / order).",
                            )
                        )

        return ScanResult(
            scanner=self.name,
            ok=True,
            grade=worst,
            score=score,
            summary=f"TLS grade {worst} (worst across {len(endpoints)} endpoint(s))",
            findings=findings,
            link=link,
        )
