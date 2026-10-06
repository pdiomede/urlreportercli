from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .scanners.base import ScanResult

# The one grading scale. Every letter shown anywhere, per scanner or overall,
# must read back to itself through this ladder; /score publishes it.
_LADDER: tuple[tuple[int, str], ...] = (
    (90, "A+"), (85, "A"), (80, "A-"),
    (75, "B+"), (70, "B"), (65, "B-"),
    (60, "C+"), (55, "C"), (50, "C-"),
    (45, "D+"), (40, "D"), (35, "D-"),
    # SSL Labs grades E between D and F. Without a rung of its own an E
    # counted as 34 and read back as F, so an SSL Labs E alone made an
    # overall F.
    (30, "E"),
)

# Every letter the ladder can produce, best first. /stats lists its grade
# distribution in this order, so a letter added above shows up there too.
GRADE_LETTERS: tuple[str, ...] = tuple(letter for _, letter in _LADDER) + ("F",)


def _band_top(letter: str) -> int:
    i = next(i for i, (_, lt) in enumerate(_LADDER) if lt == letter)
    return 100 if i == 0 else _LADDER[i - 1][0] - 1


# A letter counts as the top of its own band. This table used to sit a step
# above the ladder (A = 95, B = 80), so a letter fed into the average read
# back as a better one: an SSL Labs A alone made an overall A+, and a site
# graded B by every scanner was reported A-.
LETTER_TO_SCORE: dict[str, int] = {
    **{letter: _band_top(letter) for _, letter in _LADDER},
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
    for threshold, letter in _LADDER:
        if s >= threshold:
            return letter
    return "F"


def fit_score_to_letter(score: int, letter: str) -> int:
    """Clamp an upstream score into the ladder band of the upstream letter.

    For services that send both (Mozilla Observatory): their letter is what
    the reader sees on the service's own site, but their numeric scale is not
    ours, so their 95 beside their "A" would read back as our A+.
    """
    key = letter.strip().upper()
    floors = {lt: t for t, lt in _LADDER}
    if key in floors:
        low, high = floors[key], LETTER_TO_SCORE[key]
    elif key in LETTER_TO_SCORE:  # F, T, M: everything under the ladder
        low, high = 0, _LADDER[-1][0] - 1
    else:
        return score
    return max(low, min(score, high))


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
    # Usually the hosting provider's routing, not the site owner's doing.
    "RPKI route origin": 1.0,
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
