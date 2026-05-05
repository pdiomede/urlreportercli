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
    out.append(f"# Security report - `{report.url}`")
    out.append("")
    out.append(f"_Generated {_format_timestamp(report.generated_at)} by Url Reporter_")
    out.append("")

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
  .overall-card, table, .findings details { background: #fff; border-color: #ddd; }
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
        f"by Url Reporter</p>"
    )
    parts.append("</header>")

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
        "<p class='footnote'>Url Reporter &middot; made by "
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
