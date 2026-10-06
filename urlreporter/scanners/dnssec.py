from __future__ import annotations

import asyncio
import logging
from urllib.parse import urlparse

import httpx

from .. import publicsuffix
from ._retry import RetryExhausted, describe_exc, retry_request
from .base import Finding, ScanResult

log = logging.getLogger(__name__)

DOH_URL = "https://cloudflare-dns.com/dns-query"
# Consulted only when Cloudflare's answer is unauthenticated. See
# `_second_opinion` for why one resolver is not enough to say "not enabled".
SECOND_OPINION_URL = "https://dns.google/resolve"
REPORT_URL = "https://dnssec-analyzer.verisignlabs.com/{host}"

# DNS RR type codes, as they appear in the DoH JSON `type` field.
_TYPE_CNAME = 5
_TYPE_SOA = 6
_TYPE_DS = 43

# The second-opinion lookups are best effort and sit on the path most scans
# take (most zones are unsigned), so they retry once rather than spending the
# default 31 seconds of backoff.
_SECOND_OPINION_BACKOFFS = (3.0,)


class DNSSECScanner:
    """DNSSEC validation via Cloudflare DNS-over-HTTPS.

    Cloudflare returns AD=true when the response was DNSSEC-validated all
    the way to the root. The absence of the AD flag (with CD not set) means
    the domain either lacks DNSSEC or has a broken chain — or that Cloudflare
    is still serving answers it cached before DNSSEC was enabled, which is
    why an unauthenticated answer is checked against Google's resolver and
    the zone's DS record before it is reported as "not enabled".
    """

    name = "DNSSEC"
    config_key = "dnssec"

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
            # A DoH SOA query for "1.1.1.1" returns NXDOMAIN, which this scanner
            # rendered as "The domain does not exist. Check spelling and
            # registration status" — advice about a misspelled domain, for a
            # target that is not a domain. DNSSEC signs zones, and an IP literal
            # has none.
            return ScanResult(
                scanner=self.name, ok=True, grade=None, score=None,
                summary=(
                    f"Skipped: {host} is an IP address, so there is no DNS zone "
                    "to be signed."
                ),
                findings=[Finding(
                    severity="info",
                    title=f"DNSSEC not applicable to {host}",
                    detail=(
                        "DNSSEC signs a DNS zone. A target reached by IP address is "
                        "not resolved through one, so this scanner is excluded from "
                        "the overall score rather than reported as a lookup failure."
                    ),
                )],
                link=link,
                not_applicable=True,
            )

        try:
            resp = await retry_request(
                lambda: client.get(
                    DOH_URL,
                    params={"name": host, "type": "SOA", "do": "1"},
                    headers={"Accept": "application/dns-json"},
                    timeout=15.0,
                ),
                label=self.name, logger=log,
            )
            if resp.status_code >= 400:
                return ScanResult(scanner=self.name, ok=False,
                                  error=f"DoH returned HTTP {resp.status_code}.", link=link)
            data = resp.json()
        except RetryExhausted as e:
            log.error("%s: %s", self.name, e)
            return ScanResult(scanner=self.name, ok=False, error=str(e), link=link)
        except (httpx.HTTPError, ValueError) as e:
            return ScanResult(scanner=self.name, ok=False, error=describe_exc(e), link=link)

        ad = bool(data.get("AD"))
        rcode = data.get("Status", 0)

        if rcode != 0:
            # Translate the RCODE into a useful human message. Only SERVFAIL
            # (rcode 2) is a legitimate target-side DNSSEC failure that warrants
            # an F grade; the others are scanner-side, resolver-side, or input
            # errors and must NOT pull the weight-2.0 grade down by being
            # marked ok=True with score 0. NXDOMAIN means the domain doesn't
            # exist, REFUSED/NOTIMP mean the resolver wouldn't or couldn't
            # answer, FORMERR means we sent a malformed query.
            rcode_meta = {
                1: ("FORMERR (1)", "The query was malformed; usually a client bug, not a domain issue."),
                2: ("SERVFAIL (2)", "Often a broken DNSSEC chain. Check DS records at the registrar; mismatched DS to DNSKEY causes SERVFAIL."),
                3: ("NXDOMAIN (3)", "The domain does not exist. Check spelling and registration status; DNSSEC is not the issue here."),
                4: ("NOTIMP (4)", "The resolver does not implement this query type. Try a different DoH endpoint."),
                5: ("REFUSED (5)", "The resolver refused to answer (rate limit, ACL, or policy). Retry later or with a different resolver."),
            }
            label, advice = rcode_meta.get(
                rcode,
                (f"RCODE {rcode}", "Non-zero DNS RCODE returned; see RFC 1035 / 6895 for the meaning."),
            )
            if rcode == 2:
                return ScanResult(
                    scanner=self.name, ok=True, grade="F", score=0,
                    summary=f"DNS resolution returned {label}.",
                    findings=[Finding(
                        severity="high",
                        title=f"DNS resolution failed: {label}",
                        detail=f"The resolver returned RCODE {rcode}.",
                        recommendation=advice,
                    )],
                    link=link,
                )
            return ScanResult(
                scanner=self.name, ok=False,
                error=f"DoH returned {label}: {advice}",
                link=link,
            )

        if ad:
            return ScanResult(
                scanner=self.name, ok=True, grade="A+", score=100,
                summary="DNSSEC validates (AD flag set by Cloudflare resolver).",
                findings=[], link=link,
            )

        qname = host.rstrip(".").lower()
        apex = _zone_apex(qname, data)
        google, ds = await self._second_opinion(qname, apex, client)
        google_status = google.get("Status") if google else None
        ds_published = bool(ds and ds.get("Status") == 0 and any(
            rr.get("type") == _TYPE_DS and _name(rr) == apex
            for rr in ds.get("Answer") or []
        ))

        if google_status == 0 and google.get("AD"):
            return ScanResult(
                scanner=self.name, ok=True, grade="A+", score=100,
                summary=(
                    "DNSSEC validates (AD flag set by Google's resolver; "
                    "Cloudflare's did not set it)."
                ),
                findings=[Finding(
                    severity="info",
                    title="Cloudflare's resolver did not validate this zone; Google's did",
                    detail=(
                        "Google's resolver authenticates this zone's answers, so it is "
                        "signed and its chain to the root holds. Cloudflare's resolver "
                        "returned the same answer without the AD flag. The usual cause "
                        "is an answer it cached before DNSSEC was enabled, which it "
                        "keeps treating as unsigned until the entry expires, typically "
                        "within an hour."
                    ),
                    recommendation=(
                        "Nothing to fix on the zone. If DNSSEC was enabled recently, you "
                        "can refresh Cloudflare's cache by purging the SOA and DNSKEY "
                        "records at https://one.one.one.one/purge-cache/."
                    ),
                )],
                link=link,
            )

        if ds_published and google_status == 2:
            return ScanResult(
                scanner=self.name, ok=True, grade="F", score=0,
                summary=(
                    f"DS record published for {apex}, but Google's resolver returns "
                    "SERVFAIL: the DNSSEC chain looks broken."
                ),
                findings=[Finding(
                    severity="high",
                    title="DNSSEC chain broken: SERVFAIL on a validating resolver",
                    detail=(
                        f"The parent zone publishes a DS record for {apex}, and Google's "
                        "resolver fails to resolve this host (SERVFAIL), which is what a "
                        "validating resolver does when the DS record matches no DNSKEY in "
                        "the zone. Cloudflare's resolver still answers, most likely from "
                        "an entry cached before the DS record appeared; once it expires, "
                        "validating resolvers will all fail to resolve this domain."
                    ),
                    recommendation=(
                        "Check the DS record at your registrar against the DNSKEY your DNS "
                        "provider publishes (key tag, algorithm and digest), and correct "
                        "or remove it."
                    ),
                )],
                link=link,
            )

        alias = _alias_target(qname, data)
        if ds_published and alias and not _in_zone(alias, apex):
            return ScanResult(
                scanner=self.name, ok=True, grade="D", score=40,
                summary=(
                    f"{apex} publishes a DS record, but {qname} is an alias for "
                    f"{alias}, and the answer at the end of that chain is not signed."
                ),
                findings=[Finding(
                    severity="medium",
                    title="Hostname is an alias into an unsigned zone",
                    detail=(
                        f"{qname} is a CNAME for {alias}, outside {apex}. A resolver "
                        "can authenticate the alias itself, but the address it finally "
                        "returns comes from a zone that is not signed, so DNSSEC on "
                        f"{apex} does not protect this hostname."
                    ),
                    recommendation=(
                        "Ask your CDN or host whether it can serve this hostname from a "
                        "signed zone, or scan the apex domain to grade your own zone."
                    ),
                )],
                link=link,
            )

        if ds_published:
            # Name Google only when it answered: "AD flag clear on Google" about a
            # lookup that timed out would be a claim with nothing behind it.
            if google_status == 0:
                checked, not_validating = "Cloudflare and Google", "neither Cloudflare's nor Google's resolver authenticates"
            else:
                checked, not_validating = "Cloudflare (Google's resolver could not be asked)", "Cloudflare's resolver does not authenticate"
            return ScanResult(
                scanner=self.name, ok=True, grade="D", score=40,
                summary=(
                    f"DS record published for {apex}, but the chain does not validate "
                    f"yet (AD flag clear on {checked})."
                ),
                findings=[Finding(
                    severity="medium",
                    title="DNSSEC enabled but not validating yet",
                    detail=(
                        f"The parent zone publishes a DS record for {apex}, so DNSSEC "
                        f"has been switched on, but {not_validating} the zone's answers. "
                        "Right after DNSSEC is enabled this is expected: resolvers keep "
                        "the unsigned answers they cached earlier until those expire."
                    ),
                    recommendation=(
                        "Re-scan in an hour or two. If it still fails after a day, check "
                        "that the DS record at your registrar matches a DNSKEY your DNS "
                        "provider publishes, with an algorithm resolvers support."
                    ),
                )],
                link=link,
            )

        return ScanResult(
            scanner=self.name, ok=True, grade="D", score=40,
            summary="No DNSSEC: response was not authenticated (AD flag clear).",
            findings=[Finding(
                severity="medium",
                title="DNSSEC not enabled",
                detail="The zone is not signed, or the chain to the root cannot be validated.",
                recommendation="Enable DNSSEC at your registrar and DNS provider; publish DS records to the parent zone.",
            )],
            link=link,
        )

    async def _second_opinion(
        self, host: str, apex: str | None, client: httpx.AsyncClient,
    ) -> tuple[dict | None, dict | None]:
        """(Google's SOA answer for `host`, Cloudflare's DS answer for `apex`).

        An unauthenticated answer from one resolver is not proof the zone is
        unsigned. A resolver that cached the zone before its DS record reached
        the parent keeps serving those answers as insecure until they expire —
        so for up to an hour after a site enabled DNSSEC, this scanner graded it
        D and told its owner to go and enable DNSSEC. A second resolver with an
        independent cache, and the DS record itself, tell the two cases apart.

        Both lookups are best effort: a failure comes back as None, reads as
        "no evidence", and the caller falls back to the plain not-enabled result.
        """
        return await asyncio.gather(
            self._lookup(SECOND_OPINION_URL, host, "SOA", client),
            self._lookup(DOH_URL, apex, "DS", client) if apex else _none(),
        )

    async def _lookup(
        self, endpoint: str, name: str, rtype: str, client: httpx.AsyncClient,
    ) -> dict | None:
        try:
            resp = await retry_request(
                lambda: client.get(
                    endpoint,
                    params={"name": name, "type": rtype, "do": "1"},
                    headers={"Accept": "application/dns-json"},
                    timeout=10.0,
                ),
                label=self.name, logger=log, backoffs=_SECOND_OPINION_BACKOFFS,
            )
            if resp.status_code >= 400:
                log.warning("%s: %s %s lookup returned HTTP %d",
                            self.name, endpoint, rtype, resp.status_code)
                return None
            body = resp.json()
        except (httpx.HTTPError, ValueError) as e:
            log.warning("%s: %s %s lookup failed: %s",
                        self.name, endpoint, rtype, describe_exc(e))
            return None
        # Valid JSON is not necessarily an object. A list or a string here would
        # raise on `.get` in the caller and turn a graded D into a scanner error,
        # which is exactly what a best-effort lookup must never do.
        return body if isinstance(body, dict) else None


async def _none() -> None:
    return None


def _name(rr: dict) -> str:
    """A record's owner name, normalised: Google appends the root dot, Cloudflare doesn't."""
    return str(rr.get("name", "")).rstrip(".").lower()


def _in_zone(name: str, apex: str | None) -> bool:
    return bool(apex) and (name == apex or name.endswith("." + apex))


def _alias_target(host: str, data: dict) -> str | None:
    """Where `host` points, when the answer begins with a CNAME owned by it."""
    for rr in data.get("Answer") or []:
        if rr.get("type") == _TYPE_CNAME and _name(rr) == host:
            return str(rr.get("data", "")).rstrip(".").lower() or None
    return None


def _zone_apex(host: str, data: dict) -> str | None:
    """The apex of the zone `host` lives in, which is where its DS record hangs.

    The SOA answer names it: in the Answer section when `host` is the apex, in
    Authority when it is a name inside the zone. The owner is trusted only when
    it is `host` or an ancestor of it. A CNAME'd host is answered with the SOA
    of the zone the alias *points into*, which is someone else's — usually a
    CDN's — and its DS record says nothing about the scanned domain.
    """
    host = host.rstrip(".").lower()
    for rr in (data.get("Answer") or []) + (data.get("Authority") or []):
        if rr.get("type") != _TYPE_SOA:
            continue
        owner = _name(rr)
        if _in_zone(host, owner):
            return owner
    return publicsuffix.registrable_domain(host)
