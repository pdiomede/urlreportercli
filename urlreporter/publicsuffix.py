"""Where a hostname stops belonging to its owner and starts belonging to a registry.

Three call sites need the same boundary and each used to guess at it with
"take the last two labels": `caa` and `email_auth` walk a host's parents
looking for inherited records, and `registration` needs the registrable domain
for its RDAP query. Under a multi-label public suffix that guess is wrong in a
way that is not merely useless but actively misleading — the walk climbs *into*
the suffix and reads the registry's own DNS.

That is a live false positive, not a theoretical one. At the time of writing
`co.za` publishes both MX and SPF records, and `com.mx` publishes SPF. So
`example.co.za`, with no email authentication of its own, inherited `co.za`'s
SPF and scored for it — on a scanner weighted 2.0 — while `co.za`'s MX
suppressed the "not a mail-sending host" link-out that should have applied.
The same walk in `caa` would credit a domain with a registry's CAA policy.

This module now delegates to the real Public Suffix List via
`publicsuffixlist`, which bundles the data — no runtime download, so scanning
still makes no network call it did not already make. It replaced a curated
table that was correct for what it listed and silently wrong for everything
else; the freshness of the boundary is now tied to upgrading the package
rather than to someone remembering to add a line.

**The PRIVATE section is included on purpose.** The PSL has two halves: ICANN
(what registries sell) and PRIVATE (platforms that hand out subdomains —
`vercel.app`, `github.io`, `pages.dev`). Restricting to ICANN would put the
boundary for `myapp.vercel.app` at `vercel.app`, which is precisely the bug
this module exists to prevent: `vercel.app` publishes SPF *and* DMARC, and a
scan of an app hosted there reported A+/100 for email authentication its owner
had never configured. Whoever owns `myapp.vercel.app` cannot publish records
at `vercel.app`, so that is where their responsibility stops.

**IP literals must be screened before the library sees them.**
`PublicSuffixList().privatesuffix("1.1.1.1")` returns `"1.1"` — it treats the
address as a domain name. Delegating without the `is_ip_literal` guard below
would hand back a nonsense apex and re-open the fabricated-grade bugs on IP
targets.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from publicsuffixlist import PublicSuffixList


@lru_cache(maxsize=1)
def _psl() -> "PublicSuffixList":
    """The bundled Public Suffix List, parsed once.

    Constructed lazily: parsing the list costs ~25ms, and `urlreporter
    --version` and `--help` have no reason to pay it. Cached for the process.
    """
    from publicsuffixlist import PublicSuffixList

    return PublicSuffixList()  # PRIVATE section included — see module docstring


def is_ip_literal(host: str) -> bool:
    """True when `host` is an IP address rather than a DNS name.

    Load-bearing, not a convenience. Several scanners check properties defined
    *against a name* — CAA, SPF/DMARC/DKIM, HSTS preload, DNSSEC — and none can
    exist for an IP literal, so grading one answers a question nobody asked.
    It also screens input the PSL itself gets wrong: `privatesuffix("1.1.1.1")`
    returns `"1.1"`.
    """
    cleaned = host.strip().strip(".")
    if not cleaned:
        return False
    try:
        ipaddress.ip_address(cleaned)
    except ValueError:
        return False
    return True


def public_suffix(host: str) -> str:
    """The suffix portion of `host` — the part registered *under*, not *by*."""
    cleaned = host.lower().strip().strip(".")
    if not cleaned:
        return ""
    found = _psl().publicsuffix(cleaned)
    # An unknown TLD has no entry; the last label is the PSL's own default rule.
    return found or cleaned.split(".")[-1]


def registrable_domain(host: str) -> str | None:
    """The apex a person or company actually owns: one label below the suffix.

    ``www.example.co.uk`` -> ``example.co.uk``; ``myapp.vercel.app`` ->
    ``myapp.vercel.app``. Returns None when there is no such thing to extract:
    an IP literal, or a bare public suffix like ``co.uk`` itself.
    """
    cleaned = host.lower().strip().strip(".")
    if not cleaned or is_ip_literal(cleaned):
        return None
    return _psl().privatesuffix(cleaned)


def parent_domains(host: str) -> list[str]:
    """`host` and each ancestor down to the registrable domain, closest first.

    The walk **stops at the apex**, which is the whole point: SPF does not climb
    at all (RFC 7208) and DMARC climbs only to the Organizational Domain
    (RFC 7489 §6.6.3, defined via a public suffix list). Neither inherits from a
    registry or a hosting platform. For CAA, which does, see `ancestor_domains`.
    """
    cleaned = host.lower().strip().strip(".")
    apex = registrable_domain(cleaned)
    if apex is None:
        # A bare public suffix has nothing beneath it worth walking. A
        # single-label name ("localhost") is not a suffix at all, so it stays
        # its own leaf.
        return [] if "." in cleaned else ([cleaned] if cleaned else [])
    labels = cleaned.split(".")
    depth = len(labels) - len(apex.split("."))
    return [".".join(labels[i:]) for i in range(depth + 1)]


def ancestor_domains(host: str) -> list[str]:
    """`host` and every parent down to the two-label boundary, closest first.

    This is **not** `parent_domains`, and the difference is deliberate — the
    three protocols that climb the DNS tree do not climb the same distance:

      * **SPF** (RFC 7208) does not climb at all.
      * **DMARC** (RFC 7489 §6.6.3) falls back to the Organizational Domain,
        defined *using a public suffix list*. It stops at the apex.
      * **CAA** (RFC 8659 §3) climbs `domain -> Parent(domain)` toward the root
        and does **not** exclude public suffixes.

    So a CAA record on `vercel.app` genuinely constrains issuance for
    `myapp.vercel.app`, and one on `co.uk` genuinely constrains
    `example.co.uk`. Applying the DMARC boundary to CAA makes the scanner
    report "no CAA records on this domain or any ancestor" about a host whose
    issuance *is* restricted — false, and in the reassuring direction.
    """
    if is_ip_literal(host):
        return []
    labels = host.lower().strip().strip(".").split(".")
    return [".".join(labels[i:]) for i in range(max(len(labels) - 1, 1))]
