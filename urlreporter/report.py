from __future__ import annotations

import html as _html
import re
import textwrap

from .runner import Report
from .scanners.base import ScanResult

_URL_RE = re.compile(r"https?://[^\s<>\"')]+[^\s<>\"'),.;:!?]")

_HTTP_STATUS_RE = re.compile(r"last HTTP (\d{3})")

# Scanners that fetch the user's own origin directly (rather than going to a
# third-party API). When these get throttled, the user's site / CDN is the
# rate-limiter, not an upstream service.
_DIRECT_TARGET_SCANNERS = frozenset({
    "HTTP→HTTPS redirect",
    "DoS posture",
    "security.txt (RFC 9116)",
})

# Scanners that resolve DNS via Cloudflare DoH instead of system resolver.
_DOH_SCANNERS = frozenset({
    "CAA records",
    "DNSSEC",
    "Email auth (SPF/DMARC/DKIM)",
})

# Substrings that mean "we couldn't reach the host" at the network layer.
_UNREACHABLE_MARKERS = (
    "ConnectError",
    "Name or service not known",
    "Connection refused",
    "nodename nor servname",
    "Temporary failure in name resolution",
    "ConnectTimeout",
)


def _logs_pointer(log_path: str | None) -> str:
    """Render a user-facing pointer to the per-run log file."""
    return log_path if log_path else "./logs/error_<timestamp>.log"


def _hits_target_directly(result: ScanResult) -> bool:
    if result.scanner in _DIRECT_TARGET_SCANNERS:
        return True
    # securityheaders.com makes two calls: one to securityheaders.com (upstream)
    # and a fallback fetch of the user's origin. The retry label tells us which
    # one exhausted.
    if result.scanner == "securityheaders.com" and result.error and "direct fetch" in result.error:
        return True
    return False


def _explain_http_status(result: ScanResult, status: int, log_path: str | None = None) -> dict[str, str]:
    direct = _hits_target_directly(result)
    if status == 429:
        if direct:
            return {
                "title": "Your target rate-limited us (HTTP 429)",
                "body": (
                    "This scanner contacts your target site directly. Several scanners "
                    "run in parallel and a few of them hit your origin within milliseconds, "
                    "which can trip Cloudflare/WAF rate limits. Every retry got the same 429. "
                    "Re-run after a minute, or scan with --only / fewer checkboxes to reduce "
                    "concurrent hits."
                ),
            }
        return {
            "title": "Third-party API rate-limited us (HTTP 429)",
            "body": (
                "The third-party scanner service rate-limited us across all retries. "
                "This is not a problem with your target. Wait a minute and re-run."
            ),
        }
    if 500 <= status <= 599:
        if direct:
            return {
                "title": f"Your target returned a server error (HTTP {status})",
                "body": (
                    "This scanner contacts your target site directly, and your origin "
                    "(or its CDN) responded with a server error on every attempt. "
                    "Check whether the target is healthy, then re-run."
                ),
            }
        return {
            "title": f"Third-party scanner had a server error (HTTP {status})",
            "body": (
                "The third-party scanner service returned a server error on every retry. "
                "This is not a problem with your target. Usually transient, try again later."
            ),
        }
    if status in (408, 504):
        return {
            "title": f"Server timed out (HTTP {status})",
            "body": (
                "The endpoint accepted our connection but timed out before producing "
                "a response, on every retry. Re-run the scan."
            ),
        }
    if status == 404:
        return {
            "title": "Endpoint returned 404",
            "body": (
                "The scanner endpoint reported the resource as not found, even after "
                "retries. Some upstreams (e.g. crt.sh) return 404 under load until "
                "their cache warms; other times this is a real miss."
            ),
        }
    return {
        "title": f"HTTP {status} error",
        "body": (
            f"Every retry returned HTTP {status}. See {_logs_pointer(log_path)} "
            f"for the full request/response trace."
        ),
    }


def explain_error(result: ScanResult, log_path: str | None = None) -> dict[str, str] | None:
    """Return a plain-English explanation of why a scanner errored, or None.

    Output shape: ``{"title": str, "body": str}``. Designed to back a "What does
    this mean?" expandable section on the report. Returns None for non-errored
    results or when we have no canned guidance for the error string.
    """
    if result.ok or not result.error:
        return None
    err = result.error

    if result.scanner == "SSL Labs" and "Timed out after" in err:
        return {
            "title": "SSL Labs is still assessing your site",
            "body": (
                "SSL Labs runs a 1-3 minute live assessment on cache miss. With "
                "SSL_LABS_USE_CACHE=true, the second run on the same host typically "
                "completes in seconds because SSL Labs serves the cached result. "
                "Retry, or scan with --only excluding ssl_labs."
            ),
        }

    is_unreachable = any(m in err for m in _UNREACHABLE_MARKERS)

    if result.scanner in _DOH_SCANNERS and (
        is_unreachable
        or "cloudflare-dns" in err.lower()
        or ("last error" in err and "gave up after" in err)
    ):
        return {
            "title": "Cloudflare DoH was unreachable",
            "body": (
                "This scanner uses Cloudflare's public DoH endpoint "
                "(https://cloudflare-dns.com/dns-query) to resolve DNS records. "
                "The lookups failed at the network layer on every retry. Re-run "
                "when your network reaches Cloudflare again."
            ),
        }

    status_match = _HTTP_STATUS_RE.search(err)
    if status_match:
        return _explain_http_status(result, int(status_match.group(1)), log_path=log_path)

    if _hits_target_directly(result) and is_unreachable:
        return {
            "title": "Could not connect to your target",
            "body": (
                "DNS lookup or TCP connection to the host failed on every retry. "
                "Verify the URL works in a browser from this machine, and that no "
                "firewall is blocking outbound TLS to the target."
            ),
        }

    if "last error" in err and "gave up after" in err:
        return {
            "title": "Network error",
            "body": (
                "Repeated network-level failures while contacting the scanner endpoint "
                "(connection refused, DNS failure, or socket timeout). Every retry hit "
                "the same problem. Re-run the scan; if it persists, check your network "
                f"and the per-run log at {_logs_pointer(log_path)}."
            ),
        }

    if "API Key" in err and "securityheaders" in err.lower():
        return {
            "title": "securityheaders.com requires an API key for letter grades",
            "body": (
                "securityheaders.com no longer returns the X-Grade header to "
                "unauthenticated clients - they sell that as a paid API. We normally "
                "fall back to fetching your target's headers directly and surfacing the "
                "missing security headers as findings. If this report shows no findings "
                "for this scanner, the direct fetch also failed (target unreachable or "
                "blocking us)."
            ),
        }

    return {
        "title": "Unexpected scanner failure",
        "body": (
            "The scanner raised an exception that wasn't an HTTP or network error. "
            f"Look in {_logs_pointer(log_path)} for the full traceback."
        ),
    }


def _esc(value: object) -> str:
    return _html.escape("" if value is None else str(value), quote=True)


def _format_timestamp(dt) -> str:
    """Format a UTC datetime as e.g. '3/May/2026 at 22:33 UTC'."""
    return f"{dt.day}/{dt.strftime('%b')}/{dt.year} at {dt.strftime('%H:%M')} UTC"


def _format_date(dt) -> str:
    """Format a UTC datetime as e.g. '12/Mar/2026' (no time)."""
    return f"{dt.day}/{dt.strftime('%b')}/{dt.year}"


def _format_age(days: int | None) -> str:
    """Render a day count as 'N years', 'N months', or 'N days'."""
    if days is None:
        return ""
    if days < 0:
        days = abs(days)
    if days >= 365:
        years = days // 365
        return f"{years} year" + ("s" if years != 1 else "")
    if days >= 30:
        # Cap at 11 so 360-364 days don't render as "12 months"; the very
        # next day rolls into the years branch as "1 year".
        months = min(days // 30, 11)
        return f"{months} month" + ("s" if months != 1 else "")
    return f"{days} day" + ("s" if days != 1 else "")


def _registration_summary_line(reg) -> str:
    """One-line text summary of registration (for the terminal summary block)."""
    if reg is None:
        return ""
    bits: list[str] = []
    if reg.registrar:
        bits.append(f"Registrar: {reg.registrar}")
    if reg.expires is not None:
        days = reg.days_until_expiry
        if days is not None and days < 0:
            bits.append(f"EXPIRED {_format_age(days)} ago ({_format_date(reg.expires)})")
        elif days is not None:
            bits.append(f"Expires {_format_date(reg.expires)} ({_format_age(days)})")
    if not bits:
        return ""
    return "Registration: " + " · ".join(bits)


def _registration_security_line(reg) -> str:
    """One-line text summary of registration security signals (for the terminal summary block).

    Surfaces Registrar lock, Registry lock, and DNSSEC. Returns an empty string when no
    signal is determinate (e.g. some ccTLDs return no RDAP status codes), so the caller
    can skip the line entirely instead of printing 'Security: ' on its own.
    """
    if reg is None:
        return ""
    bits: list[str] = []
    if reg.locked is True:
        bits.append("Registrar lock On")
    elif reg.locked is False:
        bits.append("Registrar lock Off")
    if reg.registry_locked is True:
        bits.append("Registry lock On")
    elif reg.registry_locked is False:
        bits.append("Registry lock Off")
    if reg.dnssec is True:
        bits.append("DNSSEC Signed")
    elif reg.dnssec is False:
        bits.append("DNSSEC Unsigned")
    if not bits:
        return ""
    return "Security: " + " · ".join(bits)


def _render_registration_html(reg) -> list[str]:
    """Render the Registration card for the HTML report. Empty list when no data."""
    if reg is None:
        return []
    # Two-row layout: row 1 = identity/dates, row 2 = security signals.
    cells_row1: list[tuple[str, str, str, str | None]] = []  # (label, value_html, urgency, tooltip)
    cells_row2: list[tuple[str, str, str, str | None]] = []
    if reg.registrar:
        if reg.registrar_url:
            v = (
                f"<a href='{_esc(reg.registrar_url)}' target='_blank' "
                f"rel='noopener noreferrer'>{_esc(reg.registrar)}</a>"
            )
        else:
            v = _esc(reg.registrar)
        cells_row1.append(("Registrar", v, "", None))
    if reg.created is not None:
        age = _format_age(reg.domain_age_days)
        sub = f"<span class='reg-sub'>{_esc(age + ' old')}</span>" if age else ""
        cells_row1.append(("Created", f"{_esc(_format_date(reg.created))}{sub}", "", None))
    if reg.expires is not None:
        days = reg.days_until_expiry
        if days is None:
            sub = ""
            urg = ""
        elif days < 0:
            sub = f"<span class='reg-sub'>expired {_esc(_format_age(days))} ago</span>"
            urg = "reg-critical"
        elif days == 0:
            # Same UTC calendar day — split by actual timestamp.
            label = "expired today" if reg.is_expired else "expires today"
            sub = f"<span class='reg-sub'>{label}</span>"
            urg = "reg-critical"
        elif days <= 30:
            sub = f"<span class='reg-sub'>in {_esc(_format_age(days))}</span>"
            urg = "reg-critical"
        elif days <= 90:
            sub = f"<span class='reg-sub'>in {_esc(_format_age(days))}</span>"
            urg = "reg-warning"
        else:
            sub = f"<span class='reg-sub'>in {_esc(_format_age(days))}</span>"
            urg = ""
        cells_row1.append(("Expires", f"{_esc(_format_date(reg.expires))}{sub}", urg, None))
    if reg.dnssec is True:
        cells_row1.append((
            "DNSSEC",
            "Signed",
            "reg-good",
            "A DS record is published in the parent zone. Resolvers can validate "
            "the chain of trust and detect tampered DNS responses.",
        ))
    elif reg.dnssec is False:
        cells_row1.append((
            "DNSSEC",
            "Unsigned",
            "",
            "No DS record is published in the parent zone, so DNS responses cannot "
            "be cryptographically validated. Cache-poisoning or MITM attacks on "
            "resolvers could redirect this domain undetected.",
        ))
    if reg.locked is True:
        cells_row2.append((
            "Registrar lock",
            "On <span class='reg-sub'>via your registrar account</span>",
            "reg-good",
            "Transfer, update, and delete are blocked at the registrar (client*Prohibited). "
            "Standard protection against casual transfer or modification. A determined "
            "attacker who compromises the registrar account can disable this. For stronger "
            "protection, see Registry lock (the cell to the right).",
        ))
    elif reg.locked is False:
        cells_row2.append((
            "Registrar lock",
            "Off <span class='reg-sub'>via your registrar account</span>",
            "reg-warning",
            "Domain transfers and changes are not blocked at the registrar. Anyone with "
            "registrar-account access could move this domain or modify nameservers. Best "
            "practice: enable transfer lock at your registrar; for high-value domains also "
            "ask about Registry lock (registry-level protection with out-of-band auth).",
        ))
    if reg.registry_locked is True:
        cells_row2.append((
            "Registry lock",
            "On <span class='reg-sub'>via the TLD registry (out-of-band auth)</span>",
            "reg-good",
            "Registry-level lock is active (serverUpdateProhibited and/or related codes). "
            "Changes to nameservers, contacts, or DNSSEC require out-of-band verification at "
            "the registry; even a compromised registrar account cannot lift it. The strongest "
            "available domain-level protection against DNS-hijack and unauthorized-transfer attacks.",
        ))
    elif reg.registry_locked is False:
        cells_row2.append((
            "Registry lock",
            "Off <span class='reg-sub'>via the TLD registry (out-of-band auth)</span>",
            "reg-warning",
            "No registry-level lock is set. Without serverUpdateProhibited, a compromised "
            "registrar account can swap nameservers and redirect this domain. This is the attack "
            "vector behind several real-world DNS-hijack incidents on high-value sites. For "
            "high-value domains, ask your registrar about Registry Lock; it adds out-of-band "
            "verification at the registry layer (most TLD registries offer it, often as a paid add-on).",
        ))
    if reg.name_servers:
        ns_count = len(reg.name_servers)
        if ns_count == 1:
            ns_urg = "reg-warning"
            ns_sub = "RFC violation (need 2+)"
            ns_tip = (
                "Single nameserver violates RFC 1912 §2.3, which says \"you should "
                "have at least two name servers for every domain\". If this NS goes "
                "down or its provider is compromised, the entire domain becomes "
                "unreachable or hijackable. Add at least one secondary nameserver."
            )
        elif ns_count <= 6:
            ns_urg = "reg-good"
            ns_sub = "RFC-compliant" if ns_count == 2 else "healthy count"
            ns_tip = (
                "Two or more nameservers, the RFC 1912 §2.3 recommended minimum. "
                "Healthy configuration for typical production domains. Consider 3+ "
                "across multiple providers if availability is critical."
            )
        else:
            ns_urg = ""
            ns_sub = "above typical"
            ns_tip = (
                "More than the typical 2-4 nameservers. Not a problem; some large "
                "operators publish many for global redundancy or anycast diversity."
            )
        cells_row2.append((
            "Nameservers",
            f"{ns_count} <span class='reg-sub'>{ns_sub}</span>",
            ns_urg,
            ns_tip,
        ))
    if reg.registrant_country:
        cells_row2.append(("Registrant country", _esc(reg.registrant_country), "", None))
    if not (cells_row1 or cells_row2):
        return []
    parts: list[str] = []
    parts.append("<section class='registration-card'>")
    parts.append("<p class='section-eyebrow'>// registration</p>")
    parts.append(f"<h2>Domain: <code>{_esc(reg.domain)}</code></h2>")
    for cells_list, row_class in ((cells_row1, "reg-grid-row1"), (cells_row2, "reg-grid-row2")):
        if not cells_list:
            continue
        parts.append(f"<div class='reg-grid {row_class}'>")
        for label, value_html, urg, tip in cells_list:
            parts.append(f"<div class='reg-cell {urg}'>")
            if tip:
                tip_esc = _esc(tip)
                info = (
                    f"<span class='reg-info' tabindex='0' "
                    f"aria-label='{tip_esc}'>"
                    f"<span class='reg-info-icon' aria-hidden='true'>&#9432;</span>"
                    f"<span class='reg-info-tip' role='tooltip'>{tip_esc}</span>"
                    f"</span>"
                )
            else:
                info = ""
            parts.append(f"<div class='reg-label'>{_esc(label)}{info}</div>")
            parts.append(f"<div class='reg-value'>{value_html}</div>")
            parts.append("</div>")
        parts.append("</div>")
    if reg.name_servers:
        ns = ", ".join(_esc(n) for n in reg.name_servers[:6])
        if len(reg.name_servers) > 6:
            ns += f", +{len(reg.name_servers) - 6} more"
        parts.append(f"<p class='reg-ns'><span class='reg-ns-label'>Name servers:</span> {ns}</p>")
    parts.append("</section>")
    return parts


def _render_registration_md(reg) -> list[str]:
    """Render the Registration section for the markdown report. Empty list when no data."""
    if reg is None:
        return []
    rows: list[tuple[str, str]] = []
    if reg.registrar:
        if reg.registrar_url:
            rows.append(("Registrar", f"[{reg.registrar}]({reg.registrar_url})"))
        else:
            rows.append(("Registrar", reg.registrar))
    if reg.created is not None:
        age = _format_age(reg.domain_age_days)
        rows.append(("Created", f"{_format_date(reg.created)}" + (f" ({age} old)" if age else "")))
    if reg.expires is not None:
        days = reg.days_until_expiry
        urgency = ""
        if days is not None:
            if days < 0:
                urgency = f" — **EXPIRED {_format_age(days)} ago**"
            elif days == 0:
                # Same UTC calendar day — split by actual timestamp.
                urgency = " — **EXPIRED today**" if reg.is_expired else " — **expires today**"
            elif days <= 30:
                urgency = f" — **expires in {_format_age(days)}**"
            elif days <= 90:
                urgency = f" — expires in {_format_age(days)}"
            else:
                urgency = f" (in {_format_age(days)})"
        rows.append(("Expires", f"{_format_date(reg.expires)}{urgency}"))
    if reg.updated is not None:
        rows.append(("Last changed", _format_date(reg.updated)))
    if reg.locked is True:
        rows.append(("Registrar lock", "On (via your registrar account)"))
    elif reg.locked is False:
        rows.append(("Registrar lock", "Off (via your registrar account)"))
    if reg.registry_locked is True:
        rows.append(("Registry lock", "On (via the TLD registry, out-of-band auth)"))
    elif reg.registry_locked is False:
        rows.append(("Registry lock", "Off (via the TLD registry, out-of-band auth)"))
    if reg.dnssec is True:
        rows.append(("DNSSEC at registry", "Signed"))
    elif reg.dnssec is False:
        rows.append(("DNSSEC at registry", "Unsigned"))
    if reg.name_servers:
        ns_count = len(reg.name_servers)
        ns = ", ".join(reg.name_servers[:4])
        if ns_count > 4:
            ns += f", +{ns_count - 4} more"
        if ns_count == 1:
            ns_state = "RFC violation; need 2+"
        elif ns_count <= 6:
            ns_state = "RFC-compliant" if ns_count == 2 else "healthy count"
        else:
            ns_state = "above typical"
        rows.append(("Name servers", f"{ns} ({ns_count}, {ns_state})"))
    if reg.registrant_country:
        rows.append(("Registrant country", reg.registrant_country))
    if not rows:
        return []
    out: list[str] = []
    out.append("## Registration")
    out.append("")
    out.append(f"_Domain: `{reg.domain}`_")
    out.append("")
    for label, value in rows:
        out.append(f"- **{label}:** {value}")
    out.append("")
    return out


def _linkify_html(text: str | None) -> str:
    """Escape `text` for HTML and turn URLs into anchor tags."""
    if not text:
        return ""
    out: list[str] = []
    pos = 0
    for m in _URL_RE.finditer(text):
        out.append(_esc(text[pos:m.start()]))
        url = m.group(0)
        out.append(
            f'<a href="{_esc(url)}" target="_blank" rel="noopener noreferrer">{_esc(url)}</a>'
        )
        pos = m.end()
    out.append(_esc(text[pos:]))
    return "".join(out)


def render_summary(report: Report, log_path: str | None = None) -> str:
    """Short text block - used for stdout in the CLI and inline preview on the web page."""
    lines: list[str] = []
    lines.append(f"Security report - {report.url}")
    lines.append(f"Generated {_format_timestamp(report.generated_at)}")
    lines.append("")
    reg_line = _registration_summary_line(report.registration)
    sec_line = _registration_security_line(report.registration)
    if reg_line:
        lines.append(reg_line)
    if sec_line:
        lines.append(sec_line)
    if reg_line or sec_line:
        lines.append("")
    if report.overall_score is None:
        lines.append("Overall: no graded scanners returned a score.")
    else:
        lines.append(f"Overall: {report.overall_grade} ({report.overall_score}/100)")
    # Mirror the result page's "Scanners ok" KPI so the raw text summary
    # matches what the user sees on screen. Treats link-out scanners as ok
    # (they ran successfully, just without a number) - same as the KPI tile.
    if report.results:
        ok_count = sum(1 for r in report.results if r.ok)
        lines.append(f"Scanners: {ok_count} of {len(report.results)} ok.")
    if report.total_elapsed is not None:
        lines.append(f"Scan completed in {int(round(report.total_elapsed))}s.")
    lines.append("")
    lines.append("Per scanner:")
    for r in report.results:
        if not r.ok:
            lines.append(f"  - {r.scanner}: ERROR - {r.error}")
            explanation = explain_error(r, log_path=log_path)
            if explanation:
                lines.append(f"      ↳ {explanation['title']}")
                wrapped = textwrap.wrap(
                    explanation["body"],
                    width=78,
                    initial_indent="        ",
                    subsequent_indent="        ",
                )
                lines.extend(wrapped)
        elif r.grade is not None or r.score is not None:
            grade = r.grade or "?"
            score = f" ({r.score}/100)" if r.score is not None else ""
            lines.append(f"  - {r.scanner}: {grade}{score} - {r.summary}")
        else:
            lines.append(f"  - {r.scanner}: link-out (no public API) - {r.summary}")

    if report.recommendations:
        lines.append("")
        lines.append("Top recommendations:")
        for finding, source in report.recommendations[:5]:
            lines.append(f"  [{finding.severity}] {finding.title} ({source})")
    return "\n".join(lines)


def render_markdown(report: Report, log_path: str | None = None) -> str:
    out: list[str] = []
    # Backtick-wrap the URL so markdown renderers don't treat `_`, `*`, `~`,
    # `[` inside the URL as inline formatting in the heading.
    out.append(f"# Security report: <small>[`{report.url}`](<{report.url}>)</small>")
    out.append("")
    out.append(f"_Generated {_format_timestamp(report.generated_at)} by [Url Reporter](https://urlreporter.com/)_")
    out.append("")

    out.extend(_render_registration_md(report.registration))

    out.append("## Overall")
    out.append("")
    if report.overall_score is None:
        out.append("No graded scanners returned a score for this run.")
    else:
        out.append(f"**{report.overall_grade}** ({report.overall_score}/100)")
        graded = [r for r in report.results if r.ok and r.score is not None]
        skipped = [r for r in report.results if r.ok and r.score is None]
        failed = [r for r in report.results if not r.ok]
        out.append("")
        parts = [f"{len(graded)} graded scanner(s)"]
        if skipped:
            parts.append(
                f"{len(skipped)} link-out only ({', '.join(r.scanner for r in skipped)}) "
                f"- no public API; the report points at the external site for a manual check"
            )
        if failed:
            parts.append(f"{len(failed)} failed ({', '.join(r.scanner for r in failed)})")
        out.append("Aggregated from " + "; ".join(parts) + ".")
    if report.total_elapsed is not None:
        out.append("")
        out.append(f"_Scan completed in {int(round(report.total_elapsed))}s._")
    out.append("")

    out.append("## Top recommendations")
    out.append("")
    if not report.recommendations:
        out.append("_No actionable findings were surfaced by the scanners._")
    else:
        for i, (finding, source) in enumerate(report.recommendations, start=1):
            line = f"{i}. **[{finding.severity}]** {finding.title} - *{source}*"
            out.append(line)
            if finding.recommendation:
                out.append(f"   - {finding.recommendation}")
            elif finding.detail:
                out.append(f"   - {finding.detail}")
    out.append("")

    out.append("## Per-scanner results")
    out.append("")
    for r in report.results:
        out.extend(_render_scanner_section(r, log_path=log_path))
        out.append("")

    return "\n".join(out)


_HTML_CSS = """
:root {
  --bg: #060914;
  --surface: #0c1226;
  --raised: #131a33;
  --border: #1f2b4d;
  --border-strong: #2c3a64;
  --text: #eef1f8;
  --mute: #8e9ab8;
  --faint: #5f6a85;
  --accent: #4f8cff;
  --accent2: #66e0ff;
  --accent3: #b794ff;
  --good: #3ddc97;
  --warn: #ffb454;
  --bad: #ff5d6c;
  --grad: linear-gradient(120deg, #4f8cff 0%, #66e0ff 50%, #b794ff 100%);
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, "JetBrains Mono", monospace;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--sans);
  font-size: 15px;
  line-height: 1.55;
  -webkit-font-smoothing: antialiased;
}
body::before {
  content: "";
  position: fixed;
  top: 0; left: 0; right: 0;
  height: 1px;
  background: var(--grad);
  z-index: 100;
}
.wrap {
  max-width: 980px;
  margin: 0 auto;
  padding: 40px 32px 80px;
}
.hero { padding: 36px 0 32px; border-bottom: 1px solid var(--border); margin-bottom: 32px; }
.eyebrow {
  font-family: var(--mono);
  font-size: 15px;
  font-weight: 700;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: var(--accent2);
  margin: 0 0 14px;
}
h1 {
  font-family: var(--sans);
  font-weight: 700;
  font-size: 30px;
  line-height: 1.18;
  letter-spacing: -0.02em;
  margin: 0 0 14px;
}
h1 a { color: inherit; text-decoration: none; }
h1 code {
  font-family: var(--mono);
  font-size: 0.7em;
  font-weight: 500;
  background: transparent;
  border: 1px solid var(--border);
  padding: 4px 10px;
  border-radius: 8px;
  color: var(--accent2);
  word-break: break-all;
  display: inline-block;
  margin-left: 4px;
}
.generated {
  color: var(--mute);
  font-family: var(--mono);
  font-size: 12px;
  letter-spacing: 0.02em;
  margin: 0;
}
.generated a {
  color: inherit;
  text-decoration: none;
  transition: color 140ms;
}
.generated a:hover { color: var(--accent2); }
section { margin-bottom: 32px; }
.section-eyebrow {
  font-family: var(--mono);
  font-size: 15px;
  font-weight: 700;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: var(--accent2);
  margin: 0 0 12px;
}
h2 {
  font-family: var(--sans);
  font-weight: 600;
  font-size: 20px;
  letter-spacing: -0.01em;
  margin: 0 0 18px;
}

.registration-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 18px;
  padding: 24px 28px;
  margin-bottom: 32px;
}
.registration-card h2 { margin-bottom: 18px; font-size: 18px; }
.registration-card h2 code {
  font-family: var(--mono);
  font-size: 16px;
  color: var(--mute);
  background: rgba(255, 255, 255, 0.04);
  padding: 2px 8px;
  border-radius: 6px;
}
.reg-grid {
  display: grid;
  gap: 14px 22px;
}
.reg-grid-row1, .reg-grid-row2 {
  grid-template-columns: repeat(4, 1fr);
}
.reg-grid-row1 {
  margin-bottom: 14px;
}
@media (max-width: 720px) {
  .reg-grid-row1, .reg-grid-row2 { grid-template-columns: repeat(2, 1fr); }
}
@media (max-width: 480px) {
  .reg-grid-row1, .reg-grid-row2 { grid-template-columns: 1fr; }
}
.reg-cell {
  border-left: 2px solid var(--border-strong);
  padding: 4px 0 4px 12px;
}
.reg-cell.reg-good { border-left-color: var(--good); }
.reg-cell.reg-warning { border-left-color: var(--warn); }
.reg-cell.reg-critical { border-left-color: var(--bad); }
.reg-label {
  display: flex;
  align-items: center;
  gap: 6px;
  font-family: var(--mono);
  font-size: 11px;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--mute);
  margin-bottom: 4px;
}
.reg-info {
  position: relative;
  display: inline-flex;
  align-items: center;
  cursor: default;
  outline: none;
}
.reg-info-icon {
  color: var(--mute);
  font-size: 13px;
  line-height: 1;
  transition: color 120ms;
}
.reg-info:hover .reg-info-icon,
.reg-info:focus-visible .reg-info-icon { color: var(--text); }
.reg-info-tip {
  position: absolute;
  bottom: calc(100% + 8px);
  left: 0;
  width: max-content;
  max-width: 280px;
  background: var(--bg);
  color: var(--text);
  border: 1px solid var(--border-strong);
  padding: 8px 12px;
  border-radius: 8px;
  font-family: var(--sans);
  font-size: 12.5px;
  font-weight: 400;
  line-height: 1.45;
  text-align: left;
  text-transform: none;
  letter-spacing: normal;
  white-space: normal;
  opacity: 0;
  pointer-events: none;
  transition: opacity 140ms;
  z-index: 5;
  box-shadow: 0 12px 24px -10px rgba(0, 0, 0, 0.6);
}
.reg-info:hover .reg-info-tip,
.reg-info:focus-visible .reg-info-tip { opacity: 1; }
.reg-value {
  font-size: 15px;
  font-weight: 500;
  color: var(--text);
  line-height: 1.35;
}
.reg-cell.reg-critical .reg-value { color: var(--bad); }
.reg-cell.reg-warning .reg-value { color: var(--warn); }
.reg-value a { color: inherit; border-bottom: 1px dotted var(--border-strong); text-decoration: none; }
.reg-value a:hover { border-bottom-color: var(--accent2); }
.reg-sub {
  display: block;
  font-family: var(--mono);
  font-size: 11.5px;
  font-weight: 400;
  color: var(--mute);
  margin-top: 2px;
}
.reg-cell.reg-critical .reg-sub { color: var(--bad); }
.reg-cell.reg-warning .reg-sub { color: var(--warn); }
.reg-ns {
  margin: 16px 0 0;
  padding-top: 14px;
  border-top: 1px solid var(--border);
  font-family: var(--mono);
  font-size: 12px;
  color: var(--mute);
  word-break: break-all;
}
.reg-ns-label {
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--faint);
  margin-right: 6px;
}

.overall-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 18px;
  padding: 32px;
  position: relative;
  overflow: hidden;
}
.overall-card::before {
  content: "";
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 1px;
  background: var(--grad);
}
.grade {
  display: flex;
  align-items: baseline;
  gap: 18px;
  flex-wrap: wrap;
  margin: 0 0 12px;
}
.grade strong {
  font-family: Georgia, "Times New Roman", serif;
  font-weight: 400;
  font-size: 96px;
  line-height: 0.95;
  letter-spacing: -0.04em;
  background: var(--grad);
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
}
.grade .score {
  font-family: var(--mono);
  font-size: 16px;
  color: var(--mute);
  letter-spacing: 0.02em;
}
.grade-a strong { background: linear-gradient(120deg, #3ddc97, #66e0ff); -webkit-background-clip: text; background-clip: text; color: transparent; }
.grade-b strong { background: linear-gradient(120deg, #66e0ff, #4f8cff); -webkit-background-clip: text; background-clip: text; color: transparent; }
.grade-c strong { background: linear-gradient(120deg, #4f8cff, #b794ff); -webkit-background-clip: text; background-clip: text; color: transparent; }
.grade-d strong { background: linear-gradient(120deg, #ffb454, #ff5d6c); -webkit-background-clip: text; background-clip: text; color: transparent; }
.grade-e strong, .grade-f strong { background: linear-gradient(120deg, #ff5d6c, #b794ff); -webkit-background-clip: text; background-clip: text; color: transparent; }
.grade-unknown { color: var(--mute); font-size: 22px; }
.aggregate-summary { color: var(--mute); margin: 0; max-width: 64ch; }

table {
  width: 100%;
  border-collapse: separate;
  border-spacing: 0;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 14px;
  overflow: hidden;
  font-size: 14px;
}
th {
  text-align: left;
  padding: 12px 14px;
  font-family: var(--mono);
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: var(--faint);
  border-bottom: 1px solid var(--border);
  background: rgba(255,255,255,0.015);
}
td {
  padding: 14px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
  color: var(--text);
}
tr:last-child td { border-bottom: 0; }
td:first-child {
  font-family: var(--mono);
  font-size: 13px;
  font-weight: 500;
}
td:nth-child(2), td:nth-child(3) {
  font-family: var(--mono);
  font-weight: 600;
  color: var(--text);
}
a { color: var(--accent2); text-decoration: none; border-bottom: 1px solid rgba(102,224,255,0.3); }
a:hover { color: var(--accent); border-bottom-color: var(--accent); }

.recommendations ol {
  list-style: none;
  padding: 0;
  margin: 0;
  counter-reset: rec;
}
.recommendations li {
  counter-increment: rec;
  padding: 16px 0 16px 56px;
  border-bottom: 1px solid var(--border);
  position: relative;
}
.recommendations li:last-child { border-bottom: 0; }
.recommendations li::before {
  content: counter(rec, decimal-leading-zero);
  position: absolute;
  left: 0; top: 18px;
  font-family: var(--mono);
  font-size: 12px;
  color: var(--faint);
}
.recommendations li strong { font-weight: 600; font-size: 16px; }
.recommendations li em {
  font-style: normal;
  font-family: var(--mono);
  font-size: 12px;
  color: var(--mute);
  margin-left: 8px;
}
.rec, .detail { color: var(--mute); margin-top: 8px; font-size: 14.5px; line-height: 1.5; }

.sev {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 3px 10px;
  border-radius: 999px;
  font-family: var(--mono);
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  border: 1px solid;
  margin-right: 10px;
  vertical-align: middle;
}
.sev::before {
  content: "";
  width: 5px; height: 5px;
  border-radius: 999px;
  background: currentColor;
}
.sev-critical { color: #ff8090; border-color: rgba(255, 93, 108, 0.5); background: rgba(255, 93, 108, 0.1); }
.sev-high     { color: #ffa3a3; border-color: rgba(255, 93, 108, 0.4); background: rgba(255, 93, 108, 0.06); }
.sev-medium   { color: var(--warn); border-color: rgba(255, 180, 84, 0.4); background: rgba(255, 180, 84, 0.06); }
.sev-low      { color: var(--accent2); border-color: rgba(102, 224, 255, 0.4); background: rgba(102, 224, 255, 0.06); }
.sev-info     { color: var(--good); border-color: rgba(61, 220, 151, 0.4); background: rgba(61, 220, 151, 0.06); }

.findings details {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 0;
  margin-bottom: 12px;
  overflow: hidden;
}
.findings summary {
  cursor: pointer;
  padding: 14px 18px;
  font-family: var(--mono);
  font-size: 15px;
  font-weight: 600;
  letter-spacing: 0.02em;
  user-select: none;
}
.findings summary .count { color: var(--faint); margin-left: 8px; font-weight: 500; }
.findings ul { list-style: none; padding: 0 18px 16px; margin: 0; }
.findings ul li { padding: 14px 0; border-bottom: 1px solid var(--border); font-size: 15px; }
.findings ul li:last-child { border-bottom: 0; }
.findings ul li strong { font-size: 15.5px; }

.err { color: var(--bad); font-family: var(--mono); font-size: 12.5px; }
.err-explain {
  margin-top: 10px;
  background: rgba(255, 93, 108, 0.04);
  border: 1px solid rgba(255, 93, 108, 0.2);
  border-radius: 8px;
  overflow: hidden;
}
.err-explain summary {
  cursor: pointer;
  padding: 8px 12px;
  font-family: var(--mono);
  font-size: 11.5px;
  font-weight: 500;
  letter-spacing: 0.04em;
  color: var(--mute);
  user-select: none;
  list-style: none;
}
.err-explain summary::-webkit-details-marker { display: none; }
.err-explain summary::before {
  content: "▸ ";
  color: var(--bad);
  display: inline-block;
  transition: transform 200ms;
}
.err-explain[open] summary::before { transform: rotate(90deg); }
.err-explain summary:hover { color: var(--text); }
.err-explain-body { padding: 0 14px 12px; font-size: 13px; color: var(--text); }
.err-explain-body .title { font-weight: 600; color: var(--text); margin: 0 0 6px; }
.err-explain-body p { margin: 0; color: var(--mute); line-height: 1.55; }

footer {
  margin-top: 48px;
  padding-top: 18px;
  border-top: 1px solid var(--border);
}
.footnote {
  font-family: var(--mono);
  font-size: 14px;
  font-weight: 600;
  color: var(--accent2);
  letter-spacing: 0.08em;
  margin: 0;
}
.footnote a {
  color: var(--accent2);
  text-decoration: none;
  border-bottom: 1px solid transparent;
  transition: border-color 140ms;
}
.footnote a:hover { border-bottom-color: var(--accent2); }

/* Print: switch to a clean light layout. */
@media print {
  body::before { display: none; }
  body { background: #ffffff; color: #111; }
  .wrap { max-width: none; padding: 0; }
  .overall-card, table, .findings details, .registration-card { background: #fff; border-color: #ddd; }
  .reg-cell { border-left-color: #999; }
  .reg-cell.reg-good { border-left-color: #2a8c5a; }
  .reg-cell.reg-warning { border-left-color: #b87a16; }
  .reg-cell.reg-critical { border-left-color: #b8323c; }
  .reg-cell.reg-warning .reg-value, .reg-cell.reg-warning .reg-sub { color: #b87a16; }
  .reg-cell.reg-critical .reg-value, .reg-cell.reg-critical .reg-sub { color: #b8323c; }
  /* No !important: the urgency rules above for .reg-warning .reg-sub /
     .reg-critical .reg-sub are more specific (0,0,3,0) and should win on
     warn/critical sub-text in print. With !important they were being
     forced to plain #555. */
  .reg-label, .reg-sub, .reg-ns, .reg-ns-label { color: #555; }
  .reg-info { display: none; }
  th { background: #fafafa; color: #555; }
  td, .rec, .detail, .footnote, .generated, .aggregate-summary, .grade .score { color: #333; }
  .eyebrow, .section-eyebrow, .grade-unknown { color: #555; }
  .grade strong { -webkit-text-fill-color: initial; color: #1a1a1a; background: none; }
  a { color: #0a4a8c; border-bottom-color: #0a4a8c; }
  h1 code { color: #0a4a8c; border-color: #ddd; }
  .sev { background: #f4f4f4 !important; color: #333 !important; border-color: #ddd !important; }
}
"""


def render_html(report: Report, log_path: str | None = None) -> str:
    """Render the report as a self-contained HTML document.

    Same content as the markdown report, styled to match the web UI's brand
    (dark midnight + accent gradient). All CSS is inlined; no external
    fonts or scripts; print stylesheet flips to a light, paper-friendly
    layout for archival.
    """
    parts: list[str] = []
    parts.append("<!doctype html><html lang='en'><head>")
    parts.append("<meta charset='utf-8'/>")
    parts.append("<meta name='viewport' content='width=device-width, initial-scale=1'/>")
    parts.append(f"<title>Url Reporter - {_esc(report.url)}</title>")
    parts.append(f"<style>{_HTML_CSS}</style>")
    parts.append("</head><body><main class='wrap'>")

    # Hero
    parts.append("<header class='hero'>")
    parts.append("<p class='eyebrow'>// security audit</p>")
    parts.append(
        f"<h1>Report for <a href='{_esc(report.url)}' target='_blank' rel='noopener noreferrer'>"
        f"<code>{_esc(report.url)}</code></a></h1>"
    )
    parts.append(
        f"<p class='generated'>Generated {_esc(_format_timestamp(report.generated_at))} "
        f"by <a href='https://urlreporter.com/' target='_blank' rel='noopener noreferrer'>"
        f"Url Reporter</a></p>"
    )
    parts.append("</header>")

    # Registration card (between hero and overall). Rendered only when RDAP
    # produced something. Gracefully omitted otherwise — no error, no slot.
    parts.extend(_render_registration_html(report.registration))

    # Overall card
    parts.append("<section><div class='overall-card'>")
    if report.overall_score is None:
        parts.append("<p class='grade-unknown'>No graded scanners returned a score for this run.</p>")
    else:
        grade_class = f"grade-{report.overall_grade[0].lower()}" if report.overall_grade else ""
        parts.append(f"<div class='grade {grade_class}'>")
        parts.append(f"<strong>{_esc(report.overall_grade)}</strong>")
        parts.append(f"<span class='score'>{_esc(report.overall_score)}/100</span>")
        parts.append("</div>")

        graded = [r for r in report.results if r.ok and r.score is not None]
        skipped = [r for r in report.results if r.ok and r.score is None]
        failed = [r for r in report.results if not r.ok]
        bits = [f"{len(graded)} graded scanner(s)"]
        if skipped:
            bits.append(
                f"{len(skipped)} link-out only ({', '.join(_esc(r.scanner) for r in skipped)}) "
                f"- no public API; the report points at the external site for a manual check"
            )
        if failed:
            bits.append(
                f"{len(failed)} failed ({', '.join(_esc(r.scanner) for r in failed)})"
            )
        parts.append(
            f"<p class='aggregate-summary'>Aggregated from {'; '.join(bits)}.</p>"
        )
    if report.total_elapsed is not None:
        parts.append(
            f"<p class='aggregate-summary'>Scan completed in "
            f"{int(round(report.total_elapsed))}s.</p>"
        )
    parts.append("</div></section>")

    # Recommendations
    if report.recommendations:
        parts.append("<section class='recommendations'>")
        parts.append("<p class='section-eyebrow'>// recommended actions</p>")
        parts.append("<h2>Top recommendations</h2>")
        parts.append("<ol>")
        for finding, source in report.recommendations[:10]:
            parts.append("<li>")
            parts.append(f"<span class='sev sev-{_esc(finding.severity)}'>{_esc(finding.severity)}</span>")
            parts.append(f"<strong>{_linkify_html(finding.title)}</strong>")
            parts.append(f"<em>- {_esc(source)}</em>")
            if finding.recommendation:
                parts.append(f"<div class='rec'>{_linkify_html(finding.recommendation)}</div>")
            elif finding.detail:
                parts.append(f"<div class='rec'>{_linkify_html(finding.detail)}</div>")
            parts.append("</li>")
        parts.append("</ol></section>")

    # Per-scanner table
    parts.append("<section>")
    parts.append("<p class='section-eyebrow'>// per scanner</p>")
    parts.append("<h2>Scanner breakdown</h2>")
    parts.append("<table>")
    parts.append("<thead><tr><th>Scanner</th><th>Grade</th><th>Score</th><th>Summary</th></tr></thead>")
    parts.append("<tbody>")
    for r in report.results:
        parts.append("<tr>")
        if r.link:
            parts.append(
                f"<td><a href='{_esc(r.link)}' target='_blank' rel='noopener noreferrer'>"
                f"{_esc(r.scanner)}</a></td>"
            )
        else:
            parts.append(f"<td>{_esc(r.scanner)}</td>")
        parts.append(f"<td>{_esc(r.grade or '-')}</td>")
        parts.append(
            f"<td>{_esc(r.score) if r.score is not None else '-'}</td>"
        )
        parts.append("<td>")
        if r.ok:
            parts.append(_linkify_html(r.summary or ""))
            if r.score is None and r.grade is None and r.link:
                parts.append(
                    f"<div><a href='{_esc(r.link)}' target='_blank' rel='noopener noreferrer'>"
                    f"Open external scan ↗</a></div>"
                )
        else:
            parts.append(f"<span class='err'>ERROR - {_linkify_html(r.error or '')}</span>")
            explanation = explain_error(r, log_path=log_path)
            if explanation:
                parts.append("<details class='err-explain'>")
                parts.append("<summary>What does this mean?</summary>")
                parts.append("<div class='err-explain-body'>")
                parts.append(f"<p class='title'>{_esc(explanation['title'])}</p>")
                parts.append(f"<p>{_linkify_html(explanation['body'])}</p>")
                parts.append("</div></details>")
        parts.append("</td></tr>")
    parts.append("</tbody></table>")
    parts.append("</section>")

    # Detailed findings
    if any(r.findings for r in report.results):
        parts.append("<section class='findings'>")
        parts.append("<p class='section-eyebrow'>// detailed findings</p>")
        parts.append("<h2>Per-scanner findings</h2>")
        for r in report.results:
            if not r.findings:
                continue
            parts.append("<details>")
            parts.append(
                f"<summary>{_esc(r.scanner)} <span class='count'>"
                f"({len(r.findings)} findings)</span></summary>"
            )
            parts.append("<ul>")
            for f in r.findings:
                parts.append("<li>")
                parts.append(f"<span class='sev sev-{_esc(f.severity)}'>{_esc(f.severity)}</span>")
                parts.append(f"<strong>{_linkify_html(f.title)}</strong>")
                if f.detail:
                    parts.append(f"<div class='detail'>{_linkify_html(f.detail)}</div>")
                if f.recommendation:
                    parts.append(f"<div class='rec'>{_linkify_html(f.recommendation)}</div>")
                parts.append("</li>")
            parts.append("</ul></details>")
        parts.append("</section>")

    # Footer
    parts.append("<footer>")
    parts.append(
        "<p class='footnote'>"
        "<a href='https://urlreporter.com/' target='_blank' rel='noopener noreferrer'>Url Reporter</a>"
        " &middot; built by "
        "<a href='https://pdiomede.com' target='_blank' rel='noopener noreferrer'>Paolo Diomede</a>"
        "</p>"
    )
    parts.append("</footer>")

    parts.append("</main></body></html>")
    return "".join(parts)


def _render_scanner_section(r: ScanResult, log_path: str | None = None) -> list[str]:
    lines: list[str] = []
    header = f"### {r.scanner}"
    if r.grade is not None or r.score is not None:
        bits = []
        if r.grade is not None:
            bits.append(r.grade)
        if r.score is not None:
            bits.append(f"{r.score}/100")
        header += " - " + " · ".join(bits)
    elif not r.ok:
        header += " - ERROR"
    else:
        header += " - link-out (manual check on external site)"
    lines.append(header)
    lines.append("")
    if r.link:
        lines.append(f"- Link: {r.link}")
    if r.summary:
        lines.append(f"- Summary: {r.summary}")
    if not r.ok and r.error:
        lines.append(f"- Error: `{r.error}`")
        explanation = explain_error(r, log_path=log_path)
        if explanation:
            lines.append("")
            lines.append(f"  > **What does this mean?** {explanation['title']}")
            lines.append(f"  >")
            lines.append(f"  > {explanation['body']}")
    if r.findings:
        lines.append("- Findings:")
        for f in r.findings:
            entry = f"  - **[{f.severity}]** {f.title}"
            lines.append(entry)
            if f.detail:
                lines.append(f"    - {f.detail}")
            if f.recommendation:
                lines.append(f"    - _Recommendation:_ {f.recommendation}")
    return lines
