from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

import httpx

from .. import publicsuffix
from ._retry import RetryExhausted, describe_exc, retry_request
from .base import Finding, ScanResult

log = logging.getLogger(__name__)

DOH_URL = "https://cloudflare-dns.com/dns-query"
REPORT_URL = "https://dnsspy.io/scan/{host}"  # public CAA visualizer

_GENERIC_RR_RE = re.compile(r"^\\#\s+(\d+)\s+([0-9a-fA-F\s]+)$")


def _parent_domains(host: str) -> list[str]:
    """Host plus every ancestor — CAA climbs past the public suffix on purpose.

    RFC 8659 §3 defines the relevant CAA RRset by walking `domain ->
    Parent(domain)` toward the root, and it does **not** exclude public
    suffixes. A CAA record on `vercel.app` really does constrain issuance for
    `myapp.vercel.app`; one on `co.uk` really does constrain `example.co.uk`.

    This is why CAA uses `ancestor_domains` while `email_auth` uses
    `parent_domains`: DMARC stops at the Organizational Domain (RFC 7489
    §6.6.3, defined via a public suffix list) and SPF does not climb at all,
    but CAA does. Briefly giving CAA the DMARC boundary made it report "No CAA
    records on this domain or any ancestor" for hosts whose issuance *is*
    restricted — false, and false in the reassuring direction.
    """
    return publicsuffix.ancestor_domains(host)


def _decode_caa(rdata: str) -> tuple[int, str, str] | None:
    """Decode a CAA rdata string into (flags, tag, value).

    Cloudflare DoH returns CAA in two forms:
      1. presentation form: '0 issue "letsencrypt.org"'
      2. generic form: '\\# <length> <hex bytes>' (per RFC 3597)
    We accept both.
    """
    s = rdata.strip()
    m = _GENERIC_RR_RE.match(s)
    if m:
        try:
            payload = bytes.fromhex(m.group(2).replace(" ", ""))
        except ValueError:
            return None
        if len(payload) < 2:
            return None
        flags = payload[0]
        tag_len = payload[1]
        if tag_len == 0 or 2 + tag_len > len(payload):
            return None
        tag = payload[2:2 + tag_len].decode("ascii", errors="replace").lower()
        value = payload[2 + tag_len:].decode("ascii", errors="replace")
        return flags, tag, value

    # Presentation form: <flags> <tag> "<value>" (or unquoted).
    parts = s.split(None, 2)
    if len(parts) < 3:
        return None
    try:
        flags = int(parts[0])
    except ValueError:
        return None
    tag = parts[1].strip().lower()
    value = parts[2].strip().strip('"').strip("'")
    return flags, tag, value


class CAAScanner:
    """CAA record check via Cloudflare DNS-over-HTTPS.

    A domain with CAA records pins which CAs may issue certificates for it,
    cutting off whole classes of mis-issuance. CAA is inherited from
    ancestors, so we walk up if the exact host has no CAA.
    """

    name = "CAA records"
    config_key = "caa"

    async def scan(self, url: str, *, client: httpx.AsyncClient) -> ScanResult:
        host = urlparse(url).hostname
        if not host:
            return ScanResult(
                scanner=self.name, ok=False,
                error="Could not parse host from URL.",
                link=DOH_URL,
            )
        link = REPORT_URL.format(host=host)

        if publicsuffix.is_ip_literal(host):
            # CAA is published against a DNS name; an IP literal has none, so
            # there is nothing to check. Reporting "No CAA records" with a D/40
            # stated a finding about a name that cannot have one, and fed that
            # grade into the average.
            return ScanResult(
                scanner=self.name, ok=True, grade=None, score=None,
                summary=(
                    f"Skipped: {host} is an IP address, so CAA does not apply "
                    "to it."
                ),
                findings=[Finding(
                    severity="info",
                    title=f"CAA not applicable to {host}",
                    detail=(
                        "CAA records are published against a domain name. An IP "
                        "address has none, so this scanner is excluded from the "
                        "overall score rather than graded as if the records were "
                        "missing."
                    ),
                )],
                link=link,
            )

        records: list[str] = []
        matched_at: str | None = None
        # CAA is inherited from the closest ancestor that has a record. A
        # transient DoH failure on the leaf name must not abort the walk,
        # otherwise we'd miss the parent zone where the actual CAA usually
        # lives. Track per-candidate errors and only surface them if every
        # ancestor lookup fails.
        attempted = 0
        network_failures = 0
        last_error: str | None = None
        for candidate in _parent_domains(host):
            attempted += 1
            try:
                resp = await retry_request(
                    lambda c=candidate: client.get(
                        DOH_URL,
                        params={"name": c, "type": "CAA"},
                        headers={"Accept": "application/dns-json"},
                        timeout=15.0,
                    ),
                    label=f"{self.name} {candidate}", logger=log,
                )
                if resp.status_code >= 400:
                    # A non-transient HTTP error tells us nothing about the
                    # domain's CAA posture, so it counts as a failed lookup
                    # exactly like a network error does. Without this the
                    # all-ancestors-failed check below never fired for an
                    # HTTP-error-only walk and the domain was handed a
                    # "No CAA records" D/40 that fed the weighted average.
                    last_error = f"DoH returned HTTP {resp.status_code} for {candidate}"
                    network_failures += 1
                    log.warning("%s: DoH returned HTTP %d for %s", self.name, resp.status_code, candidate)
                    continue
                data = resp.json()
            except RetryExhausted as e:
                last_error = str(e)
                network_failures += 1
                log.warning("%s: %s on %s, walking up", self.name, e, candidate)
                continue
            except (httpx.HTTPError, ValueError) as e:
                last_error = describe_exc(e)
                network_failures += 1
                log.warning("%s: %s on %s, walking up", self.name, last_error, candidate)
                continue
            answers = [a for a in (data.get("Answer") or []) if a.get("type") == 257]
            if answers:
                matched_at = candidate
                records = [a.get("data", "") for a in answers]
                break

        # If every candidate raised a network/HTTP error, we have no signal
        # about the domain's CAA posture; surface that as a real error rather
        # than pretending there are no CAA records.
        if not records and attempted > 0 and network_failures == attempted:
            log.error("%s: every ancestor lookup failed (%s)", self.name, last_error)
            return ScanResult(
                scanner=self.name, ok=False,
                error=last_error or "All CAA lookups failed.",
                link=link,
            )

        findings: list[Finding] = []

        if not records:
            findings.append(Finding(
                severity="high",
                title="No CAA records found",
                detail="Without CAA, any CA that trusts your domain validation can issue a certificate for it.",
                recommendation="Add CAA records pinning issuance to your CA(s), e.g. 'example.com. CAA 0 issue \"letsencrypt.org\"'.",
            ))
            return ScanResult(
                scanner=self.name, ok=True, grade="D", score=40,
                summary="No CAA records on this domain or any ancestor.",
                findings=findings, link=link,
            )

        decoded = [d for d in (_decode_caa(r) for r in records) if d is not None]
        tags = {d[1] for d in decoded}
        has_issue = "issue" in tags or "issuewild" in tags
        has_iodef = "iodef" in tags
        # Pretty-print decoded records for the findings detail.
        pretty = [f"{d[0]} {d[1]} \"{d[2]}\"" for d in decoded] if decoded else records

        if has_issue:
            grade, score = "A+", 100
            issuers = sorted({d[2] for d in decoded if d[1] in ("issue", "issuewild")})
            summary = (
                f"{len(records)} CAA record(s) on {matched_at}; issuance restricted to "
                f"{len(issuers)} CA(s)."
            )
        elif has_iodef:
            grade, score = "C", 65
            summary = f"{len(records)} CAA record(s) on {matched_at} (iodef only, no issue restriction)."
            findings.append(Finding(
                severity="medium",
                title="CAA present but does not restrict issuance",
                detail="Only iodef (incident reporting) is set; any CA can still issue.",
                recommendation="Add an 'issue' directive to lock down which CAs may issue.",
            ))
        else:
            grade, score = "C", 65
            summary = f"{len(records)} CAA record(s) on {matched_at} (no recognized directives)."

        apex = publicsuffix.registrable_domain(host)
        if matched_at and apex and matched_at != host and len(matched_at.split(".")) < len(apex.split(".")):
            # The match is above the registrable domain, i.e. on a registry or
            # hosting platform. The protection is real (RFC 8659 climbs there),
            # but it is not this domain owner's doing and they cannot change it.
            findings.append(Finding(
                severity="info",
                title=f"CAA policy is inherited from {matched_at}, not set on {host}",
                detail=(
                    f"{matched_at} is a public suffix or hosting platform, so this "
                    f"policy covers every name under it and is outside your control. "
                    f"It does restrict issuance for {host}, but publishing your own "
                    f"CAA on a domain you control is what pins issuance to your CAs."
                ),
                recommendation=None,
            ))
        findings.append(Finding(
            severity="info",
            title=f"CAA records (matched at {matched_at})",
            detail=" | ".join(pretty[:8]) + ("…" if len(pretty) > 8 else ""),
            recommendation=None,
        ))

        return ScanResult(
            scanner=self.name, ok=True, grade=grade, score=score,
            summary=summary, findings=findings, link=link,
        )
