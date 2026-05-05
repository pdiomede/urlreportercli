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


def _parent_domains(host: str) -> list[str]:
    """Return host plus its parent labels, e.g. a.b.c -> [a.b.c, b.c]. SPF/DMARC
    are typically published at the registered domain (apex), not on every
    subdomain - so for accurate detection on a webapp host like app.aave.com we
    walk up to find records at the closest ancestor that has them."""
    parts = host.split(".")
    out: list[str] = []
    for i in range(len(parts) - 1):
        out.append(".".join(parts[i:]))
    return out or [host]


async def _doh_answers(client: httpx.AsyncClient, name: str, rrtype: str, *, label: str) -> list[dict]:
    """Generic DoH JSON lookup. Returns the raw `Answer` array on success,
    or [] on miss (NXDOMAIN, no answers, transport failure). Raises
    RetryExhausted only when every retry is a transient HTTP / network error."""
    try:
        resp = await retry_request(
            lambda: client.get(
                DOH_URL,
                params={"name": name, "type": rrtype},
                headers={"Accept": "application/dns-json"},
                timeout=15.0,
            ),
            label=label, logger=log,
        )
    except RetryExhausted:
        raise
    except (httpx.HTTPError, ValueError) as e:
        log.warning("%s DoH error for %s/%s: %s", label, name, rrtype, describe_exc(e))
        return []
    if resp.status_code >= 400:
        return []
    try:
        data = resp.json()
    except ValueError:
        return []
    return list(data.get("Answer") or [])


async def _doh_txt(client: httpx.AsyncClient, name: str, *, label: str) -> list[str]:
    """TXT records for `name`. Returns the parsed (quote-stripped) data strings."""
    answers = await _doh_answers(client, name, "TXT", label=label)
    return [_strip_quotes(a.get("data", "")) for a in answers if a.get("type") == 16 and a.get("data")]


async def _doh_has_mx(client: httpx.AsyncClient, name: str, *, label: str) -> bool:
    """True if `name` has any MX records. Used to decide whether a host (or its
    apex) is set up to receive mail at all - non-mail-sending subdomains
    legitimately don't need their own SPF/DMARC."""
    answers = await _doh_answers(client, name, "MX", label=label)
    return any(a.get("type") == 15 for a in answers)


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

    Records typically live at the registered domain (apex), not on every
    subdomain. Scanning a webapp host like app.aave.com penalizes too hard if
    we only probe the leaf - the apex records that actually protect the
    domain are at aave.com. So we walk up the parent chain looking for the
    closest ancestor that has SPF / DMARC, and grade based on what's there.

    For non-mail-sending subdomains (no MX anywhere in the chain, no SPF or
    DMARC anywhere either), email auth simply isn't applicable: the scanner
    returns a link-out result that's excluded from the overall score, rather
    than a false-positive F.

    Probes:
      - SPF:    TXT on each parent of the input host. Closest match wins.
      - DMARC:  TXT on `_dmarc.<each parent>`. Closest match wins.
      - MX:     MX on each parent. Used to detect "this is a mail domain".
      - DKIM:   TXT on `<selector>._domainkey.<host>` AND `<selector>._domainkey.<apex>`
                across 10 common selectors; reports any match.
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

        parents = _parent_domains(host)
        apex = parents[-1] if parents else host
        is_subdomain = len(parents) >= 2

        # Build query plan: SPF, DMARC, and MX for every ancestor in parallel,
        # plus DKIM on the input host (and on the apex as a fallback for
        # subdomains that may inherit DKIM-signed mail from the parent zone).
        spf_qs = [
            _doh_txt(client, p, label=f"{self.name} SPF {p}")
            for p in parents
        ]
        dmarc_qs = [
            _doh_txt(client, f"_dmarc.{p}", label=f"{self.name} DMARC {p}")
            for p in parents
        ]
        mx_qs = [
            _doh_has_mx(client, p, label=f"{self.name} MX {p}")
            for p in parents
        ]
        dkim_targets = [host] if host == apex else [host, apex]
        dkim_qs = []
        for target in dkim_targets:
            for sel in DKIM_SELECTORS:
                dkim_qs.append(
                    _doh_txt(
                        client, f"{sel}._domainkey.{target}",
                        label=f"{self.name} DKIM {sel} {target}",
                    )
                )

        try:
            results = await asyncio.gather(*spf_qs, *dmarc_qs, *mx_qs, *dkim_qs)
        except RetryExhausted as e:
            log.error("%s: %s", self.name, e)
            return ScanResult(scanner=self.name, ok=False, error=str(e), link=link)

        n = len(parents)
        spf_per_parent: list[list[str]] = list(results[0:n])
        dmarc_per_parent: list[list[str]] = list(results[n:2 * n])
        mx_per_parent: list[bool] = list(results[2 * n:3 * n])
        dkim_per_target: list[list[str]] = list(results[3 * n:])

        # Find the closest SPF / DMARC match, walking from leaf to apex.
        spf_records: list[str] = []
        spf_at: str | None = None
        for parent, recs in zip(parents, spf_per_parent):
            if any(r.lower().startswith("v=spf1") for r in recs):
                spf_records = recs
                spf_at = parent
                break

        dmarc_records: list[str] = []
        dmarc_at: str | None = None
        for parent, recs in zip(parents, dmarc_per_parent):
            if any(r.lower().startswith("v=dmarc1") for r in recs):
                dmarc_records = recs
                dmarc_at = parent
                break

        # MX presence anywhere in the chain.
        has_mx = any(mx_per_parent)

        # DKIM: try host first, then apex.
        dkim_records: list[str] = []
        dkim_selector_hit: str | None = None
        dkim_at: str | None = None
        n_sel = len(DKIM_SELECTORS)
        for i, target in enumerate(dkim_targets):
            slot_start = i * n_sel
            slot = dkim_per_target[slot_start:slot_start + n_sel]
            for sel, got in zip(DKIM_SELECTORS, slot):
                filtered = [r for r in got if "v=DKIM1" in r or "k=" in r or "p=" in r]
                if filtered:
                    dkim_records = filtered
                    dkim_selector_hit = sel
                    dkim_at = target
                    break
            if dkim_records:
                break

        # ---- MX-aware skip ----
        # If the input host is a subdomain (3+ labels), and we found NO email
        # records and NO MX anywhere in its parent chain, this isn't a
        # mail-sending host. Treat as link-out: the scanner ran successfully,
        # but there's nothing to grade. The aggregator excludes link-outs from
        # the overall score, so a webapp subdomain doesn't drag the average.
        if is_subdomain and not spf_records and not dmarc_records and not has_mx:
            return ScanResult(
                scanner=self.name, ok=True, grade=None, score=None,
                summary=(
                    f"Skipped: {host} is a subdomain with no MX, SPF, or DMARC anywhere "
                    f"up to {apex}. Not a mail-sending host."
                ),
                findings=[Finding(
                    severity="info",
                    title=f"Email auth not applicable to {host}",
                    detail=(
                        f"Walked parent chain [{', '.join(parents)}] looking for SPF, "
                        f"DMARC, or MX records. Found none. Subdomains that don't send or "
                        f"receive mail don't need their own email-auth records - that "
                        f"protection lives at the apex ({apex}) for the whole zone."
                    ),
                )],
                link=link,
            )

        # ---- Score (same scoring math as before, against the records we found) ----
        spf_hits_records = [r for r in spf_records if r.lower().startswith("v=spf1")]
        spf_qualifier = _parse_spf_policy(spf_hits_records[0]) if spf_hits_records else ""
        dmarc_hits_records = [r for r in dmarc_records if r.lower().startswith("v=dmarc1")]
        dmarc_p, dmarc_sp = _parse_dmarc_policy(dmarc_hits_records[0]) if dmarc_hits_records else ("", "")

        score = 0
        # SPF: 35 pts. Strict (-all) full credit, soft (~all) most, neutral half.
        if spf_qualifier == "-":
            score += 35
        elif spf_qualifier == "~":
            score += 28
        elif spf_qualifier in ("?", "+"):
            score += 14
        elif spf_hits_records:
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
        findings: list[Finding] = []

        # Helper for the "found via parent" suffix in titles when records live
        # on an ancestor rather than the input host.
        def _at_suffix(at: str | None) -> str:
            if at is None or at == host:
                return ""
            return f" (on {at}, inherited by {host})"

        if not spf_hits_records:
            findings.append(Finding(
                severity="high",
                title="No SPF record published",
                detail=(
                    f"Walked {host}"
                    + (f" -> {' -> '.join(parents[1:])}" if len(parents) > 1 else "")
                    + ". No SPF found at any level."
                ),
                recommendation=(
                    "Publish a TXT record on the apex domain like "
                    "'v=spf1 include:_spf.<your-mail-provider> -all'. "
                    "End with -all (hard fail) once you've inventoried every legitimate sender."
                ),
            ))
        elif spf_qualifier == "":
            findings.append(Finding(
                severity="medium",
                title="SPF record has no `all` qualifier" + _at_suffix(spf_at),
                detail=f"Found: {spf_hits_records[0][:120]}",
                recommendation="Append '-all' (or at minimum '~all') to your SPF record.",
            ))
        elif spf_qualifier == "+":
            findings.append(Finding(
                severity="high",
                title="SPF policy ends in `+all` (passes everyone)" + _at_suffix(spf_at),
                detail=f"Found: {spf_hits_records[0][:120]}",
                recommendation="`+all` is equivalent to no SPF. Replace with `-all`.",
            ))
        elif spf_qualifier == "?":
            findings.append(Finding(
                severity="low",
                title="SPF policy is neutral (`?all`)" + _at_suffix(spf_at),
                detail=f"Found: {spf_hits_records[0][:120]}",
                recommendation="Tighten to '-all' once you're confident your sender list is complete.",
            ))
        elif spf_qualifier == "~":
            findings.append(Finding(
                severity="info",
                title="SPF policy is softfail (`~all`)" + _at_suffix(spf_at),
                detail=f"Found: {spf_hits_records[0][:120]}",
                recommendation="Consider tightening to '-all' (hard fail) for stronger anti-spoofing.",
            ))
        else:
            findings.append(Finding(
                severity="info",
                title="SPF policy is hardfail (`-all`)" + _at_suffix(spf_at),
                detail=f"Found: {spf_hits_records[0][:120]}",
            ))
        if len(spf_hits_records) > 1:
            findings.append(Finding(
                severity="medium",
                title=f"Multiple SPF records on {spf_at or host}",
                detail="RFC 7208 §3.2 requires exactly one. Receivers may reject the lookup as PermError.",
                recommendation="Merge into a single TXT record.",
            ))

        if not dmarc_hits_records:
            findings.append(Finding(
                severity="high",
                title="No DMARC record published",
                detail=(
                    f"Walked _dmarc.{host}"
                    + (f" -> " + " -> ".join(f"_dmarc.{p}" for p in parents[1:]) if len(parents) > 1 else "")
                    + ". No DMARC found at any level."
                ),
                recommendation=(
                    "Publish a TXT record at _dmarc.<apex> like "
                    "'v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@<apex>'. "
                    "Start with `p=none` for monitoring, ramp to `quarantine`, then `reject`."
                ),
            ))
        elif dmarc_p == "none":
            findings.append(Finding(
                severity="medium",
                title="DMARC policy is `p=none` (monitoring only)" + _at_suffix(dmarc_at),
                detail=f"Found: {dmarc_hits_records[0][:140]}",
                recommendation="`p=none` only collects reports. Move to `p=quarantine`, then `p=reject` once your senders are aligned.",
            ))
        elif dmarc_p == "quarantine":
            findings.append(Finding(
                severity="low",
                title="DMARC policy is `p=quarantine`" + _at_suffix(dmarc_at),
                detail=f"Found: {dmarc_hits_records[0][:140]}",
                recommendation="Once you've verified DMARC reports show no false positives, move to `p=reject` for full anti-spoofing.",
            ))
        elif dmarc_p == "reject":
            findings.append(Finding(
                severity="info",
                title="DMARC policy is `p=reject`" + _at_suffix(dmarc_at),
                detail=f"Found: {dmarc_hits_records[0][:140]}",
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
                    "Probed: " + ", ".join(DKIM_SELECTORS) + " on "
                    + (f"{host} and {apex}" if host != apex else host)
                    + ". DKIM may still be configured with a non-default selector - this is not a definitive miss."
                ),
                recommendation=(
                    "Make sure your mail provider's DKIM is published (selector is provider-specific)."
                ),
            ))
        else:
            dkim_target_suffix = "" if dkim_at == host else f" on {dkim_at}"
            findings.append(Finding(
                severity="info",
                title=f"DKIM key found at selector `{dkim_selector_hit}`{dkim_target_suffix}",
                detail=dkim_records[0][:160] + ("…" if len(dkim_records[0]) > 160 else ""),
            ))

        # ---- Summary line ----
        bits = []
        if spf_at and spf_at != host:
            bits.append(f"SPF on {spf_at}")
        else:
            bits.append("SPF " + (spf_qualifier + "all" if spf_qualifier else "missing" if not spf_hits_records else "no-all"))
        if dmarc_at and dmarc_at != host:
            bits.append(f"DMARC on {dmarc_at} (p={dmarc_p})")
        else:
            bits.append("DMARC " + (f"p={dmarc_p}" if dmarc_p else "missing"))
        bits.append("DKIM " + (f"sel={dkim_selector_hit}" if dkim_records else "not found"))
        summary = "; ".join(bits)

        return ScanResult(
            scanner=self.name, ok=True, grade=grade, score=score,
            summary=summary, findings=findings, link=link,
        )
