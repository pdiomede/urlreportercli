from __future__ import annotations

import asyncio
import logging
import re
from urllib.parse import urlparse

import httpx

from ._retry import RetryExhausted, describe_exc, retry_request
from .base import Finding, ScanResult

log = logging.getLogger(__name__)

DOH_URL = "https://cloudflare-dns.com/dns-query"
REPORT_URL = "https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{host}"

# Common DKIM selectors we'll probe - most domains pick one of these.
DKIM_SELECTORS = (
    "default", "google", "selector1", "selector2",
    "mail", "k1", "k2", "dkim", "s1", "s2",
)


def _strip_quotes(s: str) -> str:
    """DoH returns TXT data already concatenated; strings can still come back
    quoted ("v=spf1 ..."). Strip wrapping quotes if present."""
    s = s.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1]
    return s


async def _doh_txt(client: httpx.AsyncClient, name: str, *, label: str) -> list[str]:
    """Look up TXT records for `name` via Cloudflare DoH. Returns [] on miss
    (NXDOMAIN, no answers, transport failure). Raises RetryExhausted only when
    every retry is a transient HTTP / network error."""
    try:
        resp = await retry_request(
            lambda: client.get(
                DOH_URL,
                params={"name": name, "type": "TXT"},
                headers={"Accept": "application/dns-json"},
                timeout=15.0,
            ),
            label=label, logger=log,
        )
    except RetryExhausted:
        raise
    except (httpx.HTTPError, ValueError) as e:
        log.warning("%s DoH error for %s: %s", label, name, describe_exc(e))
        return []
    if resp.status_code >= 400:
        return []
    try:
        data = resp.json()
    except ValueError:
        return []
    answers = [a for a in (data.get("Answer") or []) if a.get("type") == 16]
    return [_strip_quotes(a.get("data", "")) for a in answers if a.get("data")]


_SPF_ALL_RE = re.compile(r"(?:^|\s)([-~?+])all(?:\s|;|$)")


def _parse_spf_policy(record: str) -> str:
    """Return the all-qualifier from an SPF record: '-' (fail), '~' (softfail),
    '?' (neutral), '+' (pass), or '' (no `all` mechanism).

    Anchored on whitespace / start / end / ';' explicitly: a plain `\\b`
    boundary doesn't work here because `[-~?+]` and the preceding space are
    both non-word characters, so there is no word boundary between them.
    """
    m = _SPF_ALL_RE.search(record)
    return m.group(1) if m else ""


def _parse_dmarc_policy(record: str) -> tuple[str, str]:
    """Return (p, sp) tags from a DMARC record. Empty string if not set."""
    p = ""
    sp = ""
    for kv in record.split(";"):
        kv = kv.strip()
        if "=" not in kv:
            continue
        k, v = kv.split("=", 1)
        k = k.strip().lower()
        v = v.strip().lower()
        if k == "p":
            p = v
        elif k == "sp":
            sp = v
    return p, sp


class EmailAuthScanner:
    """DMARC / SPF / DKIM check via Cloudflare DNS-over-HTTPS.

    Email-spoofing protection is one of the cheapest, highest-impact wins on
    a domain: every modern mailbox provider rejects unauthenticated mail
    purporting to come from yourdomain.com if you publish strict SPF + DMARC.
    We probe:

      - SPF:    TXT on the domain, looking for `v=spf1 …` with a qualifying
                `-all` (hard fail) or `~all` (soft fail).
      - DMARC:  TXT on `_dmarc.<domain>`, looking for `p=reject|quarantine|none`.
      - DKIM:   TXT on `<selector>._domainkey.<domain>` for a small set of
                common selectors; we report ANY match (we can't enumerate all
                selectors a domain may have signed with).
    """

    name = "Email auth (SPF/DMARC/DKIM)"
    config_key = "email_auth"

    async def scan(self, url: str, *, client: httpx.AsyncClient) -> ScanResult:
        host = urlparse(url).hostname
        if not host:
            return ScanResult(
                scanner=self.name, ok=False,
                error="Could not parse host from URL.",
                link=DOH_URL,
            )
        link = REPORT_URL.format(host=host)

        # Fire SPF + DMARC + every DKIM selector probe concurrently. The
        # earlier sequential loop did up to 12 round trips at ~200ms each
        # (one per selector until a hit). With gather, total time collapses
        # to a single RTT. The cost is up to 9 extra DKIM probes when the
        # first selector hits; DoH is free and rate-limit-generous.
        try:
            queries = await asyncio.gather(
                _doh_txt(client, host, label=f"{self.name} SPF"),
                _doh_txt(client, f"_dmarc.{host}", label=f"{self.name} DMARC"),
                *[
                    _doh_txt(client, f"{sel}._domainkey.{host}", label=f"{self.name} DKIM {sel}")
                    for sel in DKIM_SELECTORS
                ],
            )
        except RetryExhausted as e:
            log.error("%s: %s", self.name, e)
            return ScanResult(scanner=self.name, ok=False, error=str(e), link=link)
        spf_records, dmarc_records = queries[0], queries[1]
        dkim_results = queries[2:]
        # Pick the first selector (in DKIM_SELECTORS order) whose response
        # carries a DKIM-shaped record. Preserves the prior "first hit wins"
        # semantics deterministically.
        dkim_records: list[str] = []
        dkim_selector_hit: str | None = None
        for sel, got in zip(DKIM_SELECTORS, dkim_results):
            filtered = [r for r in got if "v=DKIM1" in r or "k=" in r or "p=" in r]
            if filtered:
                dkim_records = filtered
                dkim_selector_hit = sel
                break

        # SPF: pick the first record that starts with v=spf1 (RFC: only one
        # such record should exist; if multiple, the domain is misconfigured).
        spf_hits = [r for r in spf_records if r.lower().startswith("v=spf1")]
        spf_qualifier = _parse_spf_policy(spf_hits[0]) if spf_hits else ""
        # DMARC: first record starting with v=DMARC1.
        dmarc_hits = [r for r in dmarc_records if r.lower().startswith("v=dmarc1")]
        dmarc_p, dmarc_sp = _parse_dmarc_policy(dmarc_hits[0]) if dmarc_hits else ("", "")

        findings: list[Finding] = []

        # ---- Score ----
        score = 0
        # SPF: 35 pts. Strict (-all) full credit, soft (~all) most, neutral half.
        if spf_qualifier == "-":
            score += 35
        elif spf_qualifier == "~":
            score += 28
        elif spf_qualifier in ("?", "+"):
            score += 14
        elif spf_hits:
            score += 10  # SPF exists but no `all` qualifier - sloppy
        # DMARC: 45 pts. reject > quarantine > none.
        if dmarc_p == "reject":
            score += 45
        elif dmarc_p == "quarantine":
            score += 32
        elif dmarc_p == "none":
            score += 14
        # DKIM: 20 pts if at least one common selector publishes a key.
        if dkim_records:
            score += 20

        if score >= 95:
            grade = "A+"
        elif score >= 85:
            grade = "A"
        elif score >= 75:
            grade = "B"
        elif score >= 60:
            grade = "C"
        elif score >= 40:
            grade = "D"
        else:
            grade = "F"

        # ---- Findings ----
        if not spf_hits:
            findings.append(Finding(
                severity="high",
                title="No SPF record published",
                detail="Without SPF, any IP can send mail claiming to be from your domain.",
                recommendation=(
                    "Publish a TXT record on the apex domain like "
                    "'v=spf1 include:_spf.<your-mail-provider> -all'. "
                    "End with -all (hard fail) once you've inventoried every legitimate sender."
                ),
            ))
        elif spf_qualifier == "":
            findings.append(Finding(
                severity="medium",
                title="SPF record has no `all` qualifier",
                detail=f"Found: {spf_hits[0][:120]}",
                recommendation="Append '-all' (or at minimum '~all') to your SPF record.",
            ))
        elif spf_qualifier == "+":
            findings.append(Finding(
                severity="high",
                title="SPF policy ends in `+all` (passes everyone)",
                detail=f"Found: {spf_hits[0][:120]}",
                recommendation="`+all` is equivalent to no SPF. Replace with `-all`.",
            ))
        elif spf_qualifier == "?":
            findings.append(Finding(
                severity="low",
                title="SPF policy is neutral (`?all`)",
                detail=f"Found: {spf_hits[0][:120]}",
                recommendation="Tighten to '-all' once you're confident your sender list is complete.",
            ))
        elif spf_qualifier == "~":
            findings.append(Finding(
                severity="info",
                title="SPF policy is softfail (`~all`)",
                detail=f"Found: {spf_hits[0][:120]}",
                recommendation="Consider tightening to '-all' (hard fail) for stronger anti-spoofing.",
            ))
        else:
            findings.append(Finding(
                severity="info",
                title="SPF policy is hardfail (`-all`)",
                detail=f"Found: {spf_hits[0][:120]}",
            ))
        if len(spf_hits) > 1:
            findings.append(Finding(
                severity="medium",
                title=f"Multiple SPF records on {host}",
                detail="RFC 7208 §3.2 requires exactly one. Receivers may reject the lookup as PermError.",
                recommendation="Merge into a single TXT record.",
            ))

        if not dmarc_hits:
            findings.append(Finding(
                severity="high",
                title="No DMARC record published",
                detail="Without DMARC, receivers have no instruction on what to do with SPF/DKIM failures.",
                recommendation=(
                    "Publish a TXT record at _dmarc.<host> like "
                    "'v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@<host>'. "
                    "Start with `p=none` for monitoring, ramp to `quarantine`, then `reject`."
                ),
            ))
        elif dmarc_p == "none":
            findings.append(Finding(
                severity="medium",
                title="DMARC policy is `p=none` (monitoring only)",
                detail=f"Found: {dmarc_hits[0][:140]}",
                recommendation="`p=none` only collects reports. Move to `p=quarantine`, then `p=reject` once your senders are aligned.",
            ))
        elif dmarc_p == "quarantine":
            findings.append(Finding(
                severity="low",
                title="DMARC policy is `p=quarantine`",
                detail=f"Found: {dmarc_hits[0][:140]}",
                recommendation="Once you've verified DMARC reports show no false positives, move to `p=reject` for full anti-spoofing.",
            ))
        elif dmarc_p == "reject":
            findings.append(Finding(
                severity="info",
                title="DMARC policy is `p=reject`",
                detail=f"Found: {dmarc_hits[0][:140]}",
            ))
        # Subdomain policy if present - flag if weaker than main.
        if dmarc_sp and dmarc_p:
            order = {"none": 0, "quarantine": 1, "reject": 2}
            if order.get(dmarc_sp, 0) < order.get(dmarc_p, 0):
                findings.append(Finding(
                    severity="low",
                    title=f"DMARC subdomain policy weaker than main (sp={dmarc_sp}, p={dmarc_p})",
                    recommendation="Drop the `sp=` tag (defaults to `p=`) or set it to match.",
                ))

        if not dkim_records:
            findings.append(Finding(
                severity="low",
                title="No DKIM key found at common selectors",
                detail=(
                    "Probed: " + ", ".join(DKIM_SELECTORS) + ". DKIM may still be configured "
                    "with a non-default selector - this is not a definitive miss."
                ),
                recommendation=(
                    "Make sure your mail provider's DKIM is published (selector is provider-specific)."
                ),
            ))
        else:
            findings.append(Finding(
                severity="info",
                title=f"DKIM key found at selector `{dkim_selector_hit}`",
                detail=dkim_records[0][:160] + ("…" if len(dkim_records[0]) > 160 else ""),
            ))

        # ---- Summary line ----
        bits = []
        bits.append("SPF " + (spf_qualifier + "all" if spf_qualifier else "missing" if not spf_hits else "no-all"))
        bits.append("DMARC " + (f"p={dmarc_p}" if dmarc_p else "missing"))
        bits.append("DKIM " + (f"sel={dkim_selector_hit}" if dkim_records else "not found"))
        summary = "; ".join(bits)

        return ScanResult(
            scanner=self.name, ok=True, grade=grade, score=score,
            summary=summary, findings=findings, link=link,
        )
