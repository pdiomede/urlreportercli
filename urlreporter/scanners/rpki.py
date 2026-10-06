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

# Every address is checked up to this many per family. The cap used to be 2,
# applied in DoH's answer order, which rotates: yahoo.com publishes 6 A and 6
# AAAA records, and five scans in a row reported four different sets of
# routes. Large sites spread addresses over several prefixes and networks, so
# a sample is not the site. Past the cap, the lowest addresses are kept (so
# repeat scans agree) and the summary says how many went unchecked.
MAX_ADDRESSES_PER_FAMILY = 8

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


async def _gather(*aws):
    """`asyncio.gather` that cancels the siblings when one child fails.

    A bare gather raises on the first failure and leaves the rest running.
    The scanner then returned its error while those lookups kept retrying (up
    to 31s of backoff each) on the shared client that run_scans closes as soon
    as every scanner has reported.
    """
    tasks = [asyncio.ensure_future(a) for a in aws]
    try:
        return await asyncio.gather(*tasks)
    except BaseException:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise


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
                total = 1
            else:
                addresses, total = await self._resolve(host, client)
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
                not_applicable=True,
            )

        link = REPORT_URL.format(resource=addresses[0])
        try:
            routes, unrouted = await self._routes(addresses, client)
            if routes:
                await _gather(
                    *(self._validate(r, client) for r in routes),
                    self._name_holders(routes, client),
                )
        except _LookupError as e:
            return ScanResult(scanner=self.name, ok=False, error=str(e), link=link)

        # Said on every path that checked addresses, the skipped one included:
        # an address past the cap might be the one that is announced.
        unchecked = (
            f" Checked {len(addresses)} of the {total} addresses {host} resolves to."
            if total > len(addresses) else ""
        )

        if not routes:
            one = len(unrouted) == 1
            return ScanResult(
                scanner=self.name, ok=True, grade=None, score=None,
                summary=(
                    f"Skipped: {', '.join(unrouted)} {'is' if one else 'are'} not "
                    "announced in public BGP, so there is no route to validate."
                ) + unchecked,
                findings=[Finding(
                    severity="info",
                    title=f"{'Address' if one else 'Addresses'} not visible in public BGP",
                    detail=(
                        f"RIPEstat sees no announcement covering {'this address' if one else 'these addresses'}. "
                        "That is normal for private or reserved ranges, and means RPKI "
                        "has nothing to check. Excluded from the overall score."
                    ),
                )],
                link=link,
                not_applicable=True,
            )

        result = self._grade(routes, unrouted, link)
        result.summary += unchecked
        return result

    async def _resolve(self, host: str, client: httpx.AsyncClient) -> tuple[list[str], int]:
        """A and AAAA addresses for `host` through Cloudflare DoH, plus how
        many there were before the per-family cap.

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
            found: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
            for a in data.get("Answer") or []:
                if a.get("type") != code:
                    continue
                try:
                    found.add(ipaddress.ip_address((a.get("data") or "").strip()))
                except ValueError:
                    continue
            # Sorted, so the same records give the same report whatever order
            # the resolver rotated them into.
            return [str(a) for a in sorted(found)]

        v4, v6 = await _gather(one("A", 1), one("AAAA", 28))
        checked = v4[:MAX_ADDRESSES_PER_FAMILY] + v6[:MAX_ADDRESSES_PER_FAMILY]
        return checked, len(v4) + len(v6)

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
        infos = await _gather(
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
            holder = data.get("holder")
            return holder.strip() or None if isinstance(holder, str) else None

        names = dict(zip(asns, await _gather(*(holder(a) for a in asns))))
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
        # One finding per announcing network, like the valid ones below: the
        # remedy is the same request to the same operator, and a site with a
        # dozen addresses would otherwise fill the recommendations with
        # near-identical lines.
        unknown_by_network: dict[str, list[_Route]] = {}
        for r in unknown:
            unknown_by_network.setdefault(r.origin, []).append(r)
        for origin, group in unknown_by_network.items():
            prefixes = ", ".join(r.prefix for r in group)
            addresses = ", ".join(a for r in group for a in r.addresses)
            one = len(group) == 1
            findings.append(Finding(
                severity="medium",
                title=f"No ROA for {prefixes} ({_who(group[0])})",
                detail=(
                    f"Nothing authorises which network may announce {prefixes}, so "
                    f"a hijacked announcement of {'it' if one else 'them'} would not "
                    "be rejected by networks that enforce route origin validation. "
                    f"Affects {addresses}. This address space usually belongs to the "
                    "hosting provider or network, not to the site's owner."
                ),
                recommendation=(
                    f"Ask the operator of AS{origin} to publish "
                    f"{'a ROA' if one else 'ROAs'} for {prefixes} at their regional "
                    "internet registry. If you hold the address space yourself, "
                    "create the ROA in your RIR portal."
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
                # dict.fromkeys: a prefix announced by two networks (MOAS) is
                # two routes but one prefix, and was listed twice.
                title=f"RPKI-valid: {', '.join(dict.fromkeys(r.prefix for r in valid))}",
                detail=" ".join(
                    f"A signed ROA authorises {who} to announce {', '.join(prefixes)}."
                    for who, prefixes in by_network.items()
                ),
            ))
        if unrouted:
            one = len(unrouted) == 1
            findings.append(Finding(
                severity="info",
                title=f"Not in public BGP: {', '.join(unrouted)}",
                detail=(
                    f"No announcement covers {'this address' if one else 'these addresses'}, "
                    f"so RPKI has nothing to check for {'it' if one else 'them'}."
                ),
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
