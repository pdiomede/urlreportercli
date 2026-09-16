from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx

from . import publicsuffix
from .scanners._retry import RetryExhausted, describe_exc, retry_request

log = logging.getLogger(__name__)

IANA_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"

_bootstrap: dict[str, str] | None = None
_bootstrap_lock = asyncio.Lock()


@dataclass
class RegistrationInfo:
    """RDAP-derived registration metadata for a domain.

    All fields are optional — RDAP servers vary in what they expose, and
    some TLDs publish very little (e.g. registrant info is usually
    redacted post-GDPR). Renderers should treat every field as nullable.
    """

    domain: str
    registrar: str | None = None
    registrar_url: str | None = None
    created: datetime | None = None
    expires: datetime | None = None
    updated: datetime | None = None
    status_codes: list[str] = field(default_factory=list)
    locked: bool | None = None
    registry_locked: bool | None = None
    dnssec: bool | None = None
    name_servers: list[str] = field(default_factory=list)
    registrant_country: str | None = None
    rdap_link: str | None = None

    @property
    def days_until_expiry(self) -> int | None:
        """Calendar days from today (UTC) until expiry. Negative if past.

        Uses ``date()`` subtraction rather than ``(expires - now).days`` so the
        count is in whole calendar days. Without this, ``timedelta.days``
        floors negative deltas, making a domain that expired 30 minutes ago
        report as ``-1`` ("expired 1 day ago") and one expiring in 30 minutes
        report as ``0`` while the boundary inside the day is invisible.
        """
        if self.expires is None:
            return None
        today = datetime.now(timezone.utc).date()
        return (self.expires.date() - today).days

    @property
    def is_expired(self) -> bool:
        """True iff the expiration timestamp is strictly in the past.

        Lets renderers distinguish ``days_until_expiry == 0 and expires later
        today`` from ``days_until_expiry == 0 and already expired today``,
        which the calendar-day count alone cannot tell apart.
        """
        if self.expires is None:
            return False
        return self.expires < datetime.now(timezone.utc)

    @property
    def expiry_urgency(self) -> str:
        """One of 'critical', 'warning', 'ok', 'unknown'."""
        d = self.days_until_expiry
        if d is None:
            return "unknown"
        if d <= 30:
            return "critical"
        if d <= 90:
            return "warning"
        return "ok"

    @property
    def domain_age_days(self) -> int | None:
        """Calendar days since registration (UTC). See ``days_until_expiry``."""
        if self.created is None:
            return None
        today = datetime.now(timezone.utc).date()
        return (today - self.created.date()).days


async def _get_bootstrap(client: httpx.AsyncClient) -> dict[str, str]:
    """Fetch the IANA RDAP bootstrap once per process and cache it.

    On any failure (network, non-200, malformed JSON) we return an empty
    mapping WITHOUT populating `_bootstrap`, so the next scan gets to retry.
    Caching the empty result would silently disable registration lookups
    for the lifetime of the process after a single transient blip.
    """
    global _bootstrap
    if _bootstrap is not None:
        return _bootstrap
    async with _bootstrap_lock:
        if _bootstrap is not None:
            return _bootstrap
        try:
            resp = await retry_request(
                lambda: client.get(IANA_BOOTSTRAP_URL, timeout=15.0),
                label="iana-rdap-bootstrap", logger=log,
            )
        except (RetryExhausted, httpx.HTTPError) as e:
            log.warning("Could not fetch IANA RDAP bootstrap: %s", describe_exc(e))
            return {}
        if resp.status_code != 200:
            log.warning("IANA RDAP bootstrap returned HTTP %d", resp.status_code)
            return {}
        try:
            data = resp.json()
        except ValueError as e:
            log.warning("IANA RDAP bootstrap returned non-JSON: %s", describe_exc(e))
            return {}
        if not isinstance(data, dict):
            log.warning("IANA RDAP bootstrap returned non-dict JSON: %s", type(data).__name__)
            return {}

        out: dict[str, str] = {}
        for entry in data.get("services", []) or []:
            if not isinstance(entry, list) or len(entry) < 2:
                continue
            tlds, urls = entry[0], entry[1]
            if not isinstance(tlds, list) or not isinstance(urls, list) or not urls:
                continue
            url = next((u for u in urls if isinstance(u, str) and u.startswith("https://")), None)
            if url is None:
                url = next((u for u in urls if isinstance(u, str)), None)
            if url is None:
                continue
            url = url.rstrip("/")
            for tld in tlds:
                if isinstance(tld, str):
                    out[tld.lower()] = url
        if not out:
            log.warning("IANA RDAP bootstrap parsed but yielded no TLD entries")
            return {}
        _bootstrap = out
        return _bootstrap


def _parse_rdap_date(s: str | None) -> datetime | None:
    if not isinstance(s, str) or not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        # Normalize to UTC so all display / day-count math uses one reference
        # frame. RDAP servers SHOULD send UTC ('Z'), but RFC 3339 allows local
        # offsets; without this, a value like '2025-06-21T01:00:00+05:30'
        # would display as 21/Jun/2025 even though the UTC date is the 20th.
        dt = dt.astimezone(timezone.utc)
    return dt


def _safe_http_url(url: Any) -> str | None:
    """Return ``url`` if it uses an http(s) scheme, else ``None``.

    RDAP responses normally provide an https registrar 'about' URL, but a
    compromised or malicious registry could deliver e.g. a ``javascript:``
    URL that would execute when a user clicks the rendered link. The HTML
    escapers in every renderer (`_esc`, Jinja autoescape, markdown) only
    handle special characters — they do not strip dangerous schemes — so
    we validate at parse time and let the data flow on.
    """
    if not isinstance(url, str):
        return None
    s = url.strip()
    if not s:
        return None
    lo = s.lower()
    if lo.startswith("http://") or lo.startswith("https://"):
        return s
    return None


def _vcard_value(vcard: Any, key: str) -> str | None:
    """Pluck a typed jCard property (e.g. 'fn', 'adr', 'country-name')."""
    if not isinstance(vcard, list) or len(vcard) < 2:
        return None
    body = vcard[1]
    if not isinstance(body, list):
        return None
    for entry in body:
        if not isinstance(entry, list) or len(entry) < 4 or entry[0] != key:
            continue
        v = entry[3]
        if isinstance(v, str):
            return v
        if isinstance(v, list):
            return ", ".join(p for p in v if isinstance(p, str) and p)
    return None


def _parse_rdap(domain: str, data: dict[str, Any]) -> RegistrationInfo:
    info = RegistrationInfo(domain=domain)

    for ev in data.get("events", []) or []:
        if not isinstance(ev, dict):
            continue
        action = (ev.get("eventAction") or "").lower()
        when = _parse_rdap_date(ev.get("eventDate"))
        if when is None:
            continue
        if action == "registration":
            info.created = when
        elif action == "expiration":
            info.expires = when
        elif action == "last changed":
            info.updated = when

    raw_status = [s for s in (data.get("status") or []) if isinstance(s, str)]
    info.status_codes = raw_status
    if raw_status:
        # RDAP responses use either the EPP camelCase form ("clientTransferProhibited")
        # or the RFC 8056 space-separated form ("client transfer prohibited"). Strip
        # whitespace so both forms reduce to the same canonical token before matching.
        canon = ["".join(s.lower().split()) for s in raw_status]
        info.locked = any(
            ("clienttransferprohibited" in s
             or "clientupdateprohibited" in s
             or "clientdeleteprohibited" in s)
            for s in canon
        )
        info.registry_locked = any(
            ("servertransferprohibited" in s
             or "serverupdateprohibited" in s
             or "serverdeleteprohibited" in s)
            for s in canon
        )

    sdns = data.get("secureDNS")
    if isinstance(sdns, dict) and "delegationSigned" in sdns:
        info.dnssec = bool(sdns.get("delegationSigned"))

    nameservers: list[str] = []
    for ns in data.get("nameservers", []) or []:
        if isinstance(ns, dict):
            ldh = ns.get("ldhName")
            if isinstance(ldh, str) and ldh:
                nameservers.append(ldh.lower())
    info.name_servers = nameservers

    for ent in data.get("entities", []) or []:
        if not isinstance(ent, dict):
            continue
        roles = [r.lower() for r in (ent.get("roles") or []) if isinstance(r, str)]
        vcard = ent.get("vcardArray")
        if "registrar" in roles:
            if info.registrar is None:
                info.registrar = _vcard_value(vcard, "fn")
            for ln in ent.get("links", []) or []:
                if not isinstance(ln, dict):
                    continue
                rel = (ln.get("rel") or "").lower()
                if rel != "about":
                    continue
                safe = _safe_http_url(ln.get("href"))
                if safe:
                    info.registrar_url = safe
                    break
        if "registrant" in roles and info.registrant_country is None:
            country = _vcard_value(vcard, "country-name")
            if country:
                info.registrant_country = country
            else:
                adr = _vcard_value(vcard, "adr")
                if adr:
                    parts = [p.strip() for p in adr.split(",") if p.strip()]
                    if parts:
                        info.registrant_country = parts[-1]

    for ln in data.get("links", []) or []:
        if not isinstance(ln, dict):
            continue
        if (ln.get("rel") or "").lower() == "self":
            safe = _safe_http_url(ln.get("href"))
            if safe:
                info.rdap_link = safe
                break

    return info


def _registrable_domain(host: str) -> str | None:
    """The domain to run RDAP against.

    Previously "the last two labels", which under a multi-label public suffix
    asked the registry about itself — `www.example.co.uk` queried `co.uk`.
    That failed benignly here (404, treated as no data), but the same rule
    lived in the CAA and email-auth parent walks where it did not, so all
    three now share one definition in `publicsuffix`.
    """
    return publicsuffix.registrable_domain(host or "")


async def fetch_registration(
    url: str, client: httpx.AsyncClient
) -> RegistrationInfo | None:
    """Fetch RDAP registration metadata for the URL's domain.

    Returns None on any failure (unsupported TLD, network error, parse
    error, IP target, 404). Logs warnings but never raises to the caller —
    the registration card is purely informational and must not block or
    fail the scan.
    """
    host = urlparse(url).hostname
    domain = _registrable_domain(host or "")
    if domain is None:
        return None

    bootstrap = await _get_bootstrap(client)
    if not bootstrap:
        return None

    tld = domain.rsplit(".", 1)[-1]
    service_url = bootstrap.get(tld)
    if not service_url:
        log.info("No RDAP service for TLD .%s", tld)
        return None

    rdap_url = f"{service_url}/domain/{domain}"
    try:
        resp = await retry_request(
            lambda: client.get(
                rdap_url,
                follow_redirects=True,
                timeout=20.0,
                headers={"Accept": "application/rdap+json"},
            ),
            label="rdap", logger=log,
        )
    except RetryExhausted as e:
        log.warning("RDAP query failed for %s: %s", domain, e)
        return None
    except httpx.HTTPError as e:
        log.warning("RDAP query error for %s: %s", domain, describe_exc(e))
        return None

    if resp.status_code == 404:
        log.info("RDAP says %s not found", domain)
        return None
    if resp.status_code >= 400:
        log.warning("RDAP for %s returned HTTP %d", domain, resp.status_code)
        return None

    try:
        data = resp.json()
    except ValueError as e:
        log.warning("RDAP for %s returned non-JSON: %s", domain, describe_exc(e))
        return None

    if not isinstance(data, dict):
        return None

    try:
        return _parse_rdap(domain, data)
    except Exception:
        log.exception("RDAP parse error for %s", domain)
        return None
