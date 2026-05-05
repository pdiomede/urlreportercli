from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .scanners.base import ScanResult

LETTER_TO_SCORE: dict[str, int] = {
    "A+": 100,
    "A": 95,
    "A-": 90,
    "B+": 85,
    "B": 80,
    "B-": 75,
    "C+": 70,
    "C": 65,
    "C-": 60,
    "D+": 55,
    "D": 50,
    "D-": 45,
    "E": 40,
    "F": 0,
    "T": 0,
    "M": 0,
}


def letter_to_score(letter: str | None) -> int | None:
    if letter is None:
        return None
    key = letter.strip().upper()
    return LETTER_TO_SCORE.get(key)


def score_to_letter(score: float | int | None) -> str:
    if score is None:
        return "?"
    s = float(score)
    if s >= 90:
        return "A+"
    if s >= 85:
        return "A"
    if s >= 80:
        return "A-"
    if s >= 75:
        return "B+"
    if s >= 70:
        return "B"
    if s >= 65:
        return "B-"
    if s >= 60:
        return "C+"
    if s >= 55:
        return "C"
    if s >= 50:
        return "C-"
    if s >= 45:
        return "D+"
    if s >= 40:
        return "D"
    if s >= 35:
        return "D-"
    return "F"


# Weights reflect security impact, not just presence of a check. Keyed by
# `Scanner.name` (the display name surfaced on each ScanResult).
# Weight 2: real cryptographic / authentication posture (TLS config, HTTP best
# practices, DNS validation chain, email anti-spoofing).
# Weight 1.5: redirect and HTTP response headers - meaningful but narrower.
# Weight 1: hardening extras and hygiene markers that are valuable but optional.
SCANNER_WEIGHTS: dict[str, float] = {
    "SSL Labs": 2.0,
    "Mozilla Observatory": 2.0,
    "DNSSEC": 2.0,
    "Email auth (SPF/DMARC/DKIM)": 2.0,
    "HTTP→HTTPS redirect": 1.5,
    "securityheaders.com": 1.5,
    "CAA records": 1.0,
    "DoS posture": 1.0,
    "HSTS Preload": 1.0,
    "security.txt (RFC 9116)": 1.0,
    "crt.sh (Certificate Transparency)": 1.0,
    "internet.nl": 1.0,
}
DEFAULT_WEIGHT = 1.0


def aggregate_score(results: list[ScanResult]) -> tuple[int | None, str]:
    """Return (overall_score, overall_letter). Score is None when nothing graded.

    Uses a weighted mean over scanners that returned a numeric score; weights
    come from SCANNER_WEIGHTS keyed by `ScanResult.scanner` (the display name).
    Scanners without an explicit weight fall back to DEFAULT_WEIGHT.
    """
    weighted: list[tuple[float, float]] = []
    for r in results:
        if not r.ok or r.score is None:
            continue
        w = SCANNER_WEIGHTS.get(r.scanner, DEFAULT_WEIGHT)
        weighted.append((float(r.score), w))
    if not weighted:
        return None, "?"
    total_w = sum(w for _, w in weighted)
    avg = sum(s * w for s, w in weighted) / total_w if total_w else 0.0
    rounded = round(avg)
    return rounded, score_to_letter(rounded)
