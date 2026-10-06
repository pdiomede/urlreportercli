from __future__ import annotations

import asyncio
import ipaddress
import logging
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from .. import publicsuffix
from ._retry import RetryExhausted, describe_exc, retry_request
from .base import Finding, ScanResult

log = logging.getLogger(__name__)

DOH_URL = "https://cloudflare-dns.com/dns-query"
RIPESTAT = "https://stat.ripe.net/data/{call}/data.json"
REPORT_URL = "https://stat.ripe.net/resource/{resource}"
# RIPEstat asks heavier users to identify themselves with `sourceapp`, so a
# rate-limit conversation, if one ever happens, has a name to start from.
SOURCEAPP = "urlreporter"

# A site behind a CDN usually resolves to several addresses in one prefix.
# Checking every one would multiply RIPEstat calls for no new information, and
# checking only one could miss a second prefix with a different status.
MAX_ADDRESSES_PER_FAMILY = 2

_INVALID_DETAIL = {
    "invalid_asn": (
        "A ROA covers this prefix but authorises a different network to "
        "announce it. Networks that enforce route origin validation drop this "
        "route, and the same pattern is what a BGP hijack looks like."
    ),
    "invalid_length": (
        "A ROA authorises this network, but only for shorter prefixes than the "
        "one being announced (the ROA's maxLength is too small). Networks that "
        "enforce route origin validation drop this route, so part of the "
        "internet cannot reach the address."
    ),
}


class _LookupError(Exception):
    """One lookup in the chain failed; the message is ready for ScanResult.error."""


@dataclass
class _Route:
    prefix: str
    origin: str
    status: str  # valid | invalid_asn | invalid_length | invalid | unknown
    addresses: list[str]
    holder: str | None = None


class RPKIScanner:
    """Route Origin Validation of the site's IP addresses via RIPEstat.

    For each address: which prefix and origin AS announce it in BGP
    (`network-info`), then whether a signed ROA authorises that pair
    (`rpki-validation`). `valid` means a hijacked announcement of the same
    prefix would be rejected by networks enforcing ROV; `unknown` means no ROA
    exists, so it would not; `invalid` means the announcement seen right now
    is itself unauthorised.

    The route almost always belongs to the hosting provider or CDN rather than
    the site owner, so every finding names the network that announces it.
    """

    name = "RPKI route origin"
    config_key = "rpki"

    async def scan(self, url: str, *, client: httpx.AsyncClient) -> ScanResult:
        host = urlparse(url).hostname
        if not host:
            return ScanResult(
                scanner=self.name, ok=False,
                error="Could not parse host from URL.",
                link="https://stat.ripe.net/",
            )

        try:
            if publicsuffix.is_ip_literal(host):
                # Unlike CAA, DNSSEC or email auth, RPKI is a property of the
                # route to an address, so an IP target is checked as-is.
                addresses = [str(ipaddress.ip_address(host.strip("[]")))]
            else:
                addresses = await self._resolve(host, client)
        except _LookupError as e:
            return ScanResult(scanner=self.name, ok=False, error=str(e),
                              link="https://stat.ripe.net/")

        if not addresses:
            return ScanResult(
                scanner=self.name, ok=True, grade=None, score=None,
                summary=f"Skipped: {host} has no A or AAAA record to check.",
                findings=[Finding(
                    severity="info",
                    title=f"No IP address found for {host}",
                    detail=(
                        "Route origin validation checks the BGP route to an IP "
                        "address. This host resolved to none, so the scanner is "
                        "excluded from the overall score."
                    ),
                )],
                link="https://stat.ripe.net/",
            )

        link = REPORT_URL.format(resource=addresses[0])
        try:
            routes, unrouted = await self._routes(addresses, client)
            if routes:
                await asyncio.gather(
                    *(self._validate(r, client) for r in routes),
                    self._name_holders(routes, client),
                )
        except _LookupError as e:
            return ScanResult(scanner=self.name, ok=False, error=str(e), link=link)

        if not routes:
            return ScanResult(
                scanner=self.name, ok=True, grade=None, score=None,
                summary=(
                    f"Skipped: {', '.join(unrouted)} is not announced in public "
                    "BGP, so there is no route to validate."
                ),
                findings=[Finding(
                    severity="info",
                    title="Address not visible in public BGP",
                    detail=(
                        "RIPEstat sees no announcement covering this address. That "
                        "is normal for private or reserved ranges, and means RPKI "
                        "has nothing to check. Excluded from the overall score."
                    ),
                )],
                link=link,
            )

        return self._grade(routes, unrouted, link)

    async def _resolve(self, host: str, client: httpx.AsyncClient) -> list[str]:
        """A and AAAA addresses for `host` through Cloudflare DoH.

        DoH follows CNAME chains itself and returns the final records in the
        same answer, so filtering on record type is enough.
        """
        async def one(rtype: str, code: int) -> list[str]:
            label = f"{self.name} DoH {rtype} {host}"
            try:
                resp = await retry_request(
                    lambda: client.get(
                        DOH_URL,
                        params={"name": host, "type": rtype},
                        headers={"Accept": "application/dns-json"},
                        timeout=15.0,
                    ),
                    label=label, logger=log,
                )
                if resp.status_code >= 400:
                    raise _LookupError(
                        f"Cloudflare DoH returned HTTP {resp.status_code} for the "
                        f"{rtype} lookup of {host}."
                    )
                data = resp.json()
            except RetryExhausted as e:
                raise _LookupError(str(e)) from e
            except (httpx.HTTPError, ValueError) as e:
                raise _LookupError(f"{label}: {describe_exc(e)}") from e
            rcode = data.get("Status", 0)
            if rcode == 3:  # NXDOMAIN: the name does not exist.
                return []
            if rcode != 0:
                raise _LookupError(
                    f"Cloudflare DoH returned RCODE {rcode} for the {rtype} "
                    f"lookup of {host}."
                )
            found: list[str] = []
            for a in data.get("Answer") or []:
                if a.get("type") != code:
                    continue
                addr = (a.get("data") or "").strip()
                if addr and addr not in found:
                    found.append(addr)
            return found[:MAX_ADDRESSES_PER_FAMILY]

        v4, v6 = await asyncio.gather(one("A", 1), one("AAAA", 28))
        return v4 + v6

    async def _ripestat(self, call: str, params: dict[str, str],
                        client: httpx.AsyncClient) -> dict:
        label = f"{self.name} RIPEstat {call} {' '.join(params.values())}"
        try:
            resp = await retry_request(
                lambda: client.get(
                    RIPESTAT.format(call=call),
                    params={**params, "sourceapp": SOURCEAPP},
                    timeout=20.0,
                ),
                label=label, logger=log,
            )
            if resp.status_code >= 400:
                raise _LookupError(f"RIPEstat returned HTTP {resp.status_code} for {call}.")
            body = resp.json()
        except RetryExhausted as e:
            raise _LookupError(str(e)) from e
        except (httpx.HTTPError, ValueError) as e:
            raise _LookupError(f"{label}: {describe_exc(e)}") from e
        if body.get("status") != "ok" or not isinstance(body.get("data"), dict):
            messages = "; ".join(
                str(m[1]) for m in body.get("messages") or [] if isinstance(m, list) and len(m) > 1
            )
            raise _LookupError(
                f"RIPEstat could not answer {call}" + (f": {messages}" if messages else ".")
            )
        return body["data"]

    async def _routes(self, addresses: list[str],
                      client: httpx.AsyncClient) -> tuple[list[_Route], list[str]]:
        """Group addresses by (announced prefix, origin AS)."""
        infos = await asyncio.gather(
            *(self._ripestat("network-info", {"resource": a}, client) for a in addresses)
        )
        routes: dict[tuple[str, str], _Route] = {}
        unrouted: list[str] = []
        for addr, info in zip(addresses, infos):
            prefix = info.get("prefix") or ""
            asns = [str(a) for a in info.get("asns") or [] if str(a).strip()]
            if not prefix or not asns:
                unrouted.append(addr)
                continue
            # More than one origin (MOAS) is legitimate for anycast; each
            # announcement is validated on its own.
            for asn in asns:
                key = (prefix, asn)
                if key not in routes:
                    routes[key] = _Route(prefix=prefix, origin=asn, status="", addresses=[])
                routes[key].addresses.append(addr)
        return list(routes.values()), unrouted

    async def _validate(self, route: _Route, client: httpx.AsyncClient) -> None:
        data = await self._ripestat(
            "rpki-validation",
            {"resource": f"AS{route.origin}", "prefix": route.prefix},
            client,
        )
        route.status = (data.get("status") or "unknown").lower()

    async def _name_holders(self, routes: list[_Route], client: httpx.AsyncClient) -> None:
        """Best effort: who operates each origin AS. Never fails the scan."""
        asns = sorted({r.origin for r in routes})

        async def holder(asn: str) -> str | None:
            try:
                data = await self._ripestat("as-overview", {"resource": f"AS{asn}"}, client)
            except _LookupError as e:
                log.warning("%s: no holder name for AS%s (%s)", self.name, asn, e)
                return None
            return (data.get("holder") or "").strip() or None

        names = dict(zip(asns, await asyncio.gather(*(holder(a) for a in asns))))
        for r in routes:
            r.holder = names.get(r.origin)

    def _grade(self, routes: list[_Route], unrouted: list[str], link: str) -> ScanResult:
        findings: list[Finding] = []
        invalid = [r for r in routes if r.status.startswith("invalid")]
        valid = [r for r in routes if r.status == "valid"]
        # Anything else, including a status RIPEstat adds later, is treated as
        # "no authorisation found" rather than credited as valid.
        unknown = [r for r in routes if r not in invalid and r not in valid]
        n = len(routes)

        for r in invalid:
            findings.append(Finding(
                severity="critical",
                title=f"RPKI-invalid route: {r.prefix} announced by {_who(r)}",
                detail=(
                    _INVALID_DETAIL.get(r.status, _INVALID_DETAIL["invalid_asn"])
                    + f" Affects {', '.join(r.addresses)}."
                ),
                recommendation=(
                    f"Tell the operator of AS{r.origin} now. If the announcement is "
                    "theirs, the ROA needs correcting; if it is not, the prefix may "
                    "be hijacked."
                ),
            ))
        for r in unknown:
            findings.append(Finding(
                severity="medium",
                title=f"No ROA for {r.prefix} ({_who(r)})",
                detail=(
                    f"Nothing authorises which network may announce {r.prefix}, so "
                    "a hijacked announcement of it would not be rejected by networks "
                    f"that enforce route origin validation. Affects {', '.join(r.addresses)}. "
                    "This address space usually belongs to the hosting provider or "
                    "network, not to the site's owner."
                ),
                recommendation=(
                    f"Ask the operator of AS{r.origin} to publish a ROA for "
                    f"{r.prefix} at their regional internet registry. If you hold "
                    "the address space yourself, create the ROA in your RIR portal."
                ),
            ))
        if valid:
            # One finding for all of them: a CDN site has a valid route per
            # address family and edge, and a line each would bury the rest.
            by_network: dict[str, list[str]] = {}
            for r in valid:
                by_network.setdefault(_who(r), []).append(r.prefix)
            findings.append(Finding(
                severity="info",
                title=f"RPKI-valid: {', '.join(r.prefix for r in valid)}",
                detail=" ".join(
                    f"A signed ROA authorises {who} to announce {', '.join(prefixes)}."
                    for who, prefixes in by_network.items()
                ),
            ))
        if unrouted:
            findings.append(Finding(
                severity="info",
                title=f"Not in public BGP: {', '.join(unrouted)}",
                detail="No announcement covers these addresses, so RPKI has nothing to check for them.",
            ))

        def share(part: list[_Route]) -> str:
            return "The route is" if n == 1 else f"{len(part)} of {n} routes are"

        if invalid:
            grade, score = "F", 0
            summary = f"{share(invalid)} RPKI-invalid: announced without authorisation."
        elif unknown:
            grade, score = "B", 74
            summary = (
                f"{share(unknown)} not covered by a ROA, so a hijacked "
                "announcement would not be rejected."
            )
        else:
            grade, score = "A+", 100
            networks = ", ".join(sorted({_who(r) for r in valid}))
            every = "The route is" if n == 1 else f"All {n} routes are"
            summary = f"{every} RPKI-valid ({networks})."

        return ScanResult(
            scanner=self.name, ok=True, grade=grade, score=score,
            summary=summary, findings=findings, link=link,
        )


def _who(route: _Route) -> str:
    return f"AS{route.origin} {route.holder}" if route.holder else f"AS{route.origin}"
