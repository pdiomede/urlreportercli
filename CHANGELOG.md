# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This is the CLI distribution. Entries here are limited to changes that affect the CLI, the scan engine, scanners, grading, configuration, and on-disk report output.

## [Unreleased]

## [0.0.33] - 2026-05-05

### Notes
- **Version sync.** No engine, scanner, grading, or CLI changes. Patch level bumped to align with the urlreporter (web) repo's UI/contrast polish release.

## [0.0.32] - 2026-05-05

### Changed (raw summary now matches the report KPIs)
- **`render_summary()` now emits a `Scanners: N of M ok.` line** between the overall grade and the scan-completed line. The Markdown / HTML report renderers already had a more verbose "Aggregated from X graded scanner(s); Y link-out only (...); Z failed (...)" line in the Overall section; the raw summary's terser form is intentional - the per-scanner list directly below it already names every scanner and its outcome.
- **Counts treat link-out scanners as "ok"** (they ran successfully, they just don't return a number).

### Notes
- **Backward compatible.** Existing reports re-render with one extra line; no schema change.

## [0.0.29] - 2026-05-05

### Fixed (report parity audit: content drifts between markdown / HTML / CLI summary)
- **Generation credit case mismatch.** Markdown reports said `_Generated <ts> by urlreporter_` (lowercase package name); HTML reports said `Generated <ts> by Url Reporter` (display name). Aligned to the display name `Url Reporter` in both renderers.
- **HTML overall score format used spaces around the slash.** Markdown / CLI summary render `(87/100)`; HTML rendered `87 / 100`. Removed the spaces so the score string is consistent across all surfaces (`87/100`).
- **HTML aggregate summary dropped the link-out explainer tail.** Markdown's "Aggregated from..." line includes "1 link-out only (internet.nl) - no public API; the report points at the external site for a manual check"; HTML truncated to just "1 link-out only (internet.nl)". Ported the same explainer string to the HTML renderer.
- **`Report.total_elapsed` now appears in every report.** Both renderers append `Scan completed in {N}s.` after the aggregate summary; `render_summary()` (used as the stdout printout) gets the same line.

### Notes
- **Backward compatible.** Same `Report` dataclass, same scanner outputs.

## [0.0.28] - 2026-05-05

### Changed (within-scanner concurrency, tier A from the perf roadmap)
- **`security_headers` now fires its two HTTP calls in parallel.** The X-Grade probe at `securityheaders.com/?q=...` and the direct fetch of the user's own URL are independent. Wrapped into two inner async helpers (`_fetch_grade`, `_fetch_target`) and dispatched via `asyncio.gather(...)`. Wall time becomes `max(call)` instead of `sum(call)` - saves roughly half the scanner's time on a healthy run, ~1s in the typical case.
- **`security_txt` now probes `/.well-known/security.txt` and `/security.txt` in parallel** instead of sequentially. Previously the scanner walked the canonical path first, then fell back to the legacy path only on a 4xx - meaning the no-security.txt case (the common one for the 70th-percentile site) paid two RTTs to learn the file isn't there. With `asyncio.gather` over both candidates, that case now takes one RTT. Canonical-first preference is preserved by walking the gathered results in `(WELLKNOWN_PATH, LEGACY_PATH)` order.
- **Both scanners use the same `asyncio.gather` pattern that landed in 0.0.23 for `email_auth`** (the 12-DKIM-selector parallelization).

### Notes
- **No new dependencies.** Adds `import asyncio` to two scanner modules; otherwise just a refactor of the existing `scan()` body.
- **Backward compatible.** Same `ScanResult` shape, same scoring, same finding text, same on-disk report format.

## [0.0.26] - 2026-05-05

### Added
- **README "Install" section now starts with `git clone`** so the documentation is self-contained for new users coming in cold.

### Notes
- **Docs only.** No engine, scanner, grading, or report changes.

## [0.0.24] - 2026-05-04

### Fixed (per-scanner bug audit, 4 real bugs across 12 scanners)
- **`caa.py`: a transient DoH failure on the leaf name aborted the ancestor walk.** CAA records inherit from the closest ancestor that has them, so the walk-up over `_parent_domains(host)` is the whole point of this scanner. The previous code returned a hard error on the first `RetryExhausted` (or `httpx.HTTPError`/`ValueError`) on `www.example.com` and never tried `example.com` where the CAA record actually lives. Now each candidate's lookup failure is logged as a warning and the loop continues; an error result is only returned if **every** ancestor lookup raised.
- **`dnssec.py`: non-zero RCODE finding had identical `detail` and `recommendation` text.** The `rcode_meta` table's second tuple element was being passed as both fields. `detail` now states `"The resolver returned RCODE <n>."` and `recommendation` carries the actionable advice.
- **`dos_posture.py`: `("Generic CDN (via header)", [("via", None)])` flagged any `Via` header as a CDN.** RFC 7230 §5.7.1 requires every proxy in the chain (forward, reverse, non-CDN) to add a Via entry, so the fingerprint produced false positives. Removed the catch-all entry.
- **`internetnl.py`: setting `INTERNETNL_API_TOKEN` made the result *worse*.** Without a token the scanner emitted a link-out result. With a token configured, the scanner returned `ok=False` with the error message `"internet.nl batch-API integration is not implemented yet."`, which counted as a failed scanner. Now the token-set path also falls back to link-out (logging a WARNING so the operator knows the configured token is being ignored).

### Notes
- **Backward compatible.** Same config keys, CLI flags, and on-disk report format.

## [0.0.23] - 2026-05-04

### Changed (scanner concurrency: tier-1 speed improvements)
- **`email_auth` now fires every DNS probe in parallel.** Previously a sequential SPF lookup, then DMARC lookup, then up to ten DKIM-selector probes (`default`, `google`, `selector1`, `selector2`, `mail`, `k1`, `k2`, `dkim`, `s1`, `s2`) - early-exiting on the first DKIM hit but still one round trip at a time. Replaced the loop with a single `asyncio.gather(...)` of all 12 queries. On a healthy DoH path the scanner now completes in roughly one RTT (~200-300ms) instead of up to twelve. The first-hit-wins selector preference is preserved deterministically by walking the `DKIM_SELECTORS` tuple in order over the gathered results.
- **SSL Labs polling cadence is now adaptive.** Previous behavior: `await asyncio.sleep(10)` between every poll. New behavior: 3-second cadence for the first 4 polls (catches cache hits and DNS-lookup stalls quickly), then 10-second cadence for everything beyond. Worst case for first-time cache-miss scans is identical to before; cached scans land roughly 0-7 seconds faster.

### Notes
- **No engine changes beyond the two scanner concurrency tweaks.** Grading, retry helper, CLI, and report renderers are untouched.
- **Backward compatible.** No change to scan results, reports, or config. Just faster.

## [0.0.22] - 2026-05-04

### Added (timing data on reports)
- **`Report.total_elapsed: float | None`** is a new dataclass field in `runner.py`, populated with `round(time.monotonic() - run_started, 1)` at the end of `run_scans()`. Default `None` keeps it backwards compatible.

### Notes
- **No engine changes beyond the new field.** Scanners, grading, retry helper, and downloadable report renderers are untouched.

## [0.0.21] - 2026-05-04

### Changed (error messages)
- **Per-run log paths are now substituted into error explanations.** Three `explain_error()` strings previously contained the literal placeholder `./logs/error_<timestamp>.log`. They now interpolate the real path returned by `setup_logger()` (e.g. `/Users/.../logs/error_20260504-141230.log`) when one is known. `render_summary`, `render_markdown`, `render_html`, and `_render_scanner_section` accept a new `log_path: str | None` keyword argument; the CLI wires the real path through.
- **Error explanations are surfaced in the CLI text summary**, not just the on-disk HTML/Markdown reports. Each failed scanner now prints `↳ <title>` plus a wrapped body underneath the `ERROR -` line. Previously the user had to open the `.md` file to see the explanation.
- **Four new error-explanation patterns** are matched in `explain_error()`:
  - **SSL Labs polling timeout** (`scanner == "SSL Labs"` AND `"Timed out after"` in error). Explains the 1-3 minute live assessment, recommends retry with `SSL_LABS_USE_CACHE=true`.
  - **Cloudflare DoH unreachable** (DNS scanners CAA / DNSSEC / Email auth + network-shaped error). Explains that these scanners depend on `cloudflare-dns.com/dns-query`.
  - **Target unreachable on direct-target scanner** (`HTTP→HTTPS redirect`, `DoS posture`, `security.txt` + connection-shaped error). Explains the user's URL is unreachable from this machine and points at firewall / DNS as likely causes.
  - **Missing `INTERNETNL_API_TOKEN`** is now named explicitly in the link-out summary string (was a generic "no API token configured").
- **Two new helpers in `report.py`:** `_logs_pointer(log_path)` for consistent log-path rendering across patterns, plus `_DOH_SCANNERS` and `_UNREACHABLE_MARKERS` constants used by the new pattern matchers.

### Changed (project rename)
- **Renamed the project to `urlreporter` (display name "Url Reporter").** Affects the package directory, the console script and import path (`urlreporter.cli`), the launcher scripts (`bin/urlreporter`, `gitUrlReporter.sh`), the package logger name (`urlreporter`), the default `HTTP_USER_AGENT` (`urlreporter/0.1`), the report filename prefix (`urlreporter-<host>-<ts>.md`), and the `APP_NAME` constant.

## [0.0.20] - 2026-05-04

### Changed (scoring methodology)
- **Optional scanners no longer tank the overall grade.** `hsts_preload` previously returned `D / 40` when a domain was not on the Chrome HSTS preload list, and `security_txt` returned `F / 0` when no `/.well-known/security.txt` was published. Both are opt-in / recommended and were dragging the overall average down for sites with otherwise excellent posture. Re-scaled to reflect their actual nature as hardening / hygiene markers: `hsts_preload` now returns `B+ / 80` (not preloaded), `A / 90` (pending), `A+ / 100` (preloaded); `security_txt` returns `B- / 70` when the file is missing instead of `F / 0`. Severity of the corresponding findings was lowered from `medium` to `low`.
- **Overall grade is now a weighted mean.** Previously a plain average of all graded scanners. `grading.aggregate_score()` now weights scanners by security impact: weight 2.0 for SSL Labs, Mozilla Observatory, DNSSEC, Email auth (SPF/DMARC/DKIM); weight 1.5 for HTTP→HTTPS redirect and securityheaders.com; weight 1.0 for CAA, DoS posture, HSTS Preload, security.txt, crt.sh, internet.nl. Weights live in `SCANNER_WEIGHTS` keyed by `ScanResult.scanner` (display name). Unknown scanners fall back to `DEFAULT_WEIGHT = 1.0`.
- **Letter-grade buckets loosened by 5 points.** `score_to_letter()` thresholds shifted down so a few weak optional categories cannot push a fundamentally secure site below A-. New ladder: `>=90 A+`, `>=85 A`, `>=80 A-`, `>=75 B+`, `>=70 B`, `>=65 B-`, `>=60 C+`, `>=55 C`, `>=50 C-`, `>=45 D+`, `>=40 D`, `>=35 D-`, else `F`. The `LETTER_TO_SCORE` map (used to convert third-party letters back to numbers) is unchanged.
- **`urlreporter explain-score`** updated to describe the weighted average, the new weight table, the new letter ladder, and a revised caveat about scanner weights being a judgment call.

## [0.0.19] - 2026-05-04

### Changed (report rendering)
- **Em dashes removed across all user-facing strings.** Scanner outputs, error explanations, summary lines, and CHANGELOG/README. Replaced with hyphens or commas depending on grammatical context. House style is now em-dash-free.
- **Timestamps in reports are now human-readable.** New `_format_timestamp()` helper formats `report.generated_at` as `4/May/2026 at 22:33 UTC` instead of the previous ISO `2026-05-03T22:33:12+00:00`. Applied to the CLI summary, downloaded markdown, and downloaded HTML.
- **HTML report footer simplified.** Removed the `Config sources: ...` line. Footer now contains only `Url Reporter · made by Paolo Diomede`.
- **Markdown report footer simplified.** Same change: dropped the `_Config sources: ..._` italic line and the `---` separator above it. The downloaded `.md` ends on the credit line `_Generated <timestamp> by urlreporter_`.

### Notes
- **No engine changes.** Report renderer and the `report.py` timestamp helper.
- **Backward compatible.** Existing report files on disk render with the old timestamp until they expire; new scans use the new format.

## [0.0.14] - 2026-05-03

### Added (CLI parity)
- **`--html` flag on `scan`**. When set, the CLI writes a self-contained HTML report next to the existing Markdown one (same `report.render_html()` byte-for-byte identical output). Default off, so existing scripts keep producing only `.md`. The HTML path is `<out>.html` (i.e. `--out reports/foo.md --html` produces `reports/foo.html`).
- **Incremental report writes** during a CLI scan. After every `scanner_done` event the CLI now re-renders the partial Markdown (and HTML, if `--html`) to disk. A `Ctrl-C` mid-scan, or a `kill -9`, leaves a usable report file containing every scanner that finished before the interrupt.
- **Partial report on engine exception / interrupt.** `asyncio.run(run_scans(...))` is now wrapped in a `try/except` for both `KeyboardInterrupt` (exit 130, POSIX convention for SIGINT) and any other unexpected exception (exit 1, with a `Scan failed:` banner). In either path the CLI falls back to whatever the incremental writer last wrote, prints the partial-report path, and still emits the per-scanner summary so the user sees the partial verdict instead of a bare traceback.
- **`urlreporter explain-score`** subcommand. Prints the methodology behind the grade in plain English (letter→number table, the "skipped scanners" rule, the score-to-letter ladder, the five honest caveats). No URL argument; no network calls; exit 0.

### Notes
- **No engine changes.** All four additions reuse `runner.run_scans()`, `report.render_summary()`, `report.render_markdown()`, `report.render_html()`, `grading.aggregate_score()`, and `runner._prioritize` / `runner.Report` exactly as before.
- **Backward compatible.** Existing flags (`--config`, `--out`, `--quiet`, `--only`) and exit codes (0 success, 1 all-failed, 2 args error) are preserved.

## [0.0.13] - 2026-05-03

### Fixed (file-by-file bug audit)
- **`config.py`**: process-environment overrides only applied to keys that already existed in a loaded config file, so setting `INTERNETNL_API_TOKEN=…` (or any `SCANNER_*` toggle) in the shell with no `config.env` present was silently ignored. Replaced the `for k in merged.keys()` loop with an explicit `_RECOGNIZED_KEYS` tuple so env vars override regardless of file presence.
- **`grading.py`**: `aggregate_score()` returned `(round(avg), score_to_letter(avg))`. With an unrounded avg of, say, `94.6`, the score rounded up to `95` while the letter was still computed from `94.6` and came out as `"A"` - yielding the contradictory pair `(95, "A")` even though the documented buckets put `95 → A+`. Now derives the letter from the same rounded integer the user sees.
- **`urlutil.py`**: `_SCHEME_PREFIX_RE` matched any RFC 3986 scheme prefix, so common inputs like `localhost:3000` or `example.com:8080` were rejected as `Unsupported URL scheme: 'localhost'.` Added a host:port discriminator: when the segment after `:` parses as a port number (digits, optionally followed by `/path`), fall through to the default-https branch instead. The `javascript:` / `data:` / `file:` / `vbscript:` defenses still fire.

## [0.0.11] - 2026-05-03

### Added
- **Two new scanners** (default count is now 12, all free, no API keys):
  - **`email_auth` (SPF / DMARC / DKIM)**: TXT lookups via Cloudflare DoH for the apex SPF, `_dmarc.<host>` DMARC, and DKIM probes across 10 common selectors (`default`, `google`, `selector1`, `selector2`, `mail`, `k1`, `k2`, `dkim`, `s1`, `s2`). Scoring weights: SPF 35 pts (`-all` full credit, `~all` partial, `+all` flagged as a "passes everyone" anti-pattern), DMARC 45 pts (reject 45, quarantine 32, none 14), DKIM 20 pts on any selector hit. Findings include missing-record, no-`all`-qualifier, multiple-SPF-records (RFC 7208 §3.2 violation), `p=none` monitoring-only nag, weaker-subdomain-policy, and a DKIM-not-found-at-common-selectors low-severity hint.
  - **`security_txt` (RFC 9116)**: fetches `/.well-known/security.txt` (then `/security.txt` as a legacy fallback), parses it, and grades on canonical-location compliance, `Contact:` presence, `Expires:` presence + parseability + future-dated, plus partial credit for `Policy:`, `Encryption:`, `Acknowledgments:`, `Preferred-Languages:`. Flags `Expires` within 30 days as low-sev (renewal warning) and totally unknown field names as info-level (typo catch).

### Fixed (per-scanner audit, 4 real bugs across 12 scanners)
- **`mozilla_observatory.py`**: if the `…/{scan_id}/tests` endpoint returned `null` JSON (or any non-list / non-dict scalar), the scanner crashed with `TypeError: 'NoneType' is not iterable`. Now defaults to an empty iterable and proceeds.
- **`dnssec.py`**: a non-zero DNS RCODE was always reported as if it were `SERVFAIL=2` (broken DNSSEC chain). NXDOMAIN, REFUSED, FORMERR, NOTIMP each have very different causes and recommendations; the scanner now translates the RCODE into the correct human message and advice.
- **`dos_posture.py`**: an `Age: 0` response header was treated as cacheable, because `bool("0")` is `True` in Python. Now int-parses the value and only counts strictly positive ages.
- **`email_auth.py`** (the SPF parser): the regex `\b([-~?+])all\b` could **never** match `-all` / `~all` / `+all` / `?all` when preceded by whitespace, because `\b` requires a word↔non-word transition and both space and `-` are non-word characters. **Every** SPF policy ending in `-all` was being scored as if it had no `all` qualifier (10 pts instead of 35). Replaced with `(?:^|\s)([-~?+])all(?:\s|;|$)` which anchors on actual whitespace boundaries.

## [0.0.10] - 2026-05-03

### Added
- **HTML report renderer.** New `render_html(report)` in `report.py` produces a self-contained, no-CDN-dependency document with embedded CSS, plus a `@media print` stylesheet that flips to a clean white-on-black layout for paper/PDF export.

### Fixed (core logic)
- **`runner.py` elapsed time was always 0.0** for every scanner. `asyncio.as_completed` yields wrapper coroutines, **not** the original Task objects, so the per-task identity lookup `task in starts` always missed. Replaced with `asyncio.wait(FIRST_COMPLETED)` which returns the original tasks; per-scanner timings now reflect real wall-clock (verified live: `0.1s` / `0.5s` instead of `0.0s` / `0.0s`).
- **`scanners/ssllabs.py` used `asyncio.get_event_loop()`** inside an async function (twice), which is deprecated in Python 3.10+ and raises `DeprecationWarning`. Switched to `asyncio.get_running_loop()`.
- **`scanners/internetnl.py` `host = urlparse(url).hostname or url`** fell back to the whole URL string when hostname extraction failed, producing a broken link-out like `https://internet.nl/site/https://example.com/`. Now bails with a clean error like every other scanner.

## [0.0.9] - 2026-05-02

### Changed (CLI / markdown)
- The CLI live per-scanner progress block now reads `link-out (no public API)` (was bare `link-out`).
- The downloaded markdown report's text summary line now reads `<scanner>: link-out (no public API) - …`.
- The markdown report's overall paragraph now appends an inline explanation when any link-out scanner is present: *"… 1 link-out only (internet.nl) - no public API; the report points at the external site for a manual check."*
- The per-scanner section header for link-out scanners is now `### internet.nl - link-out (manual check on external site)`.

## [0.0.7] - 2026-05-02

### Fixed (core logic)
- **`render_markdown` heading**: the URL on the top-level `# Security report - …` line is now backtick-wrapped. Previously, URLs containing markdown-special chars (`_`, `*`, `~`, `[`) got formatted as italics / strikethrough / link syntax in many renderers (GitHub, VS Code preview, etc.).
- **`runner.run_scans`**: the user-tunable `SCAN_TIMEOUT_SECONDS` from `config.env` now actually flows through to the shared `httpx.AsyncClient` as the read timeout (clamped to [30, 300] s). Before, only SSL Labs honored this knob; everything else was hard-coded at 60 s.

## [0.0.6] - 2026-05-02

### Changed
- **Renamed user-facing product to "Url Reporter"**. CLI banner and `--version` now read `Url Reporter v0.0.6 | Made by Paolo Diomede`. The Python package, CLI command, and repo directory remain `urlreporter`.

### Added
- **`LICENSE.md`** at the repo root (MIT, 2026 Paolo Diomede). README's License section links to it.

## [0.0.5] - 2026-05-02

### Added
- **Shared retry helper** (`scanners/_retry.py`) wrapping every outbound HTTP call from the scanners. Retries on transient HTTP statuses (408, 429, 500, 502, 503, 504, 520-527, 529) and `httpx.RequestError` (timeouts, DNS failures, connection refused), with exponential backoff (3s, 8s, 20s) before giving up. Each retry is logged at WARNING level, so failed scans tell you exactly what was tried.
- **Per-scanner module loggers** - every scanner now emits to a `urlreporter.scanners.<name>` logger, which propagates to the package-level file handler. Retries, fallback paths, and supplementary-fetch failures are all captured in `logs/error_<timestamp>.log` automatically.
- **`describe_exc(e)` helper** - produces a human-readable error string even when `httpx`'s `__str__` returns empty. Avoids the previous "HTTP error: " (no detail) UX.
- **`treat_404_as_transient`** flag on the retry helper, used by crt.sh which serves 404s for valid queries when its DB is under load.

### Fixed (core logic)
- **Empty error messages** when `httpx.HTTPStatusError` (and a few other exceptions) had blank `__str__`. All scanners now use `describe_exc` so the user always sees an exception type at minimum.
- **No retries** on most scanners (only SSL Labs and crt.sh had them); now applied to Mozilla Observatory, securityheaders.com, hstspreload.org, CAA, DNSSEC, HTTP→HTTPS redirect, and DoS posture, in addition to the two that already had retries.
- **`config.py`**: `INTERNETNL_API_TOKEN` now `.strip()`s its value so users with surrounding whitespace get a clean token.
- **`config.py`**: `SCAN_TIMEOUT_SECONDS` is clamped to ≥ 10 to prevent SSL Labs polling from giving up before its first response.
- **`runner._safe_scan`** now lets `asyncio.CancelledError` propagate (so cooperative cancellation actually cancels) instead of trapping it in the broad `except Exception`.
- **`runner._emit`** wraps the user-supplied `on_event` callback in try/except so a buggy listener can no longer sink the entire scan; the failure is logged at WARNING.
- **Logger restructure**: handler is attached to the package logger (`urlreporter`) so every submodule's `logging.getLogger(__name__)` propagates to the per-run file.

## [0.0.4] - 2026-05-02

### Added
- **`dos_posture` scanner** - passive DoS / DDoS resilience check. Sends a single GET to the URL (zero load generated) and inspects response headers for: CDN/WAF fingerprints (Cloudflare, Akamai, Fastly, AWS CloudFront, Google GFE, Azure Front Door, Sucuri, Imperva, KeyCDN, StackPath, BunnyCDN, CDN77, Vercel, Netlify, GitHub Pages, Varnish), positive-`max-age` / `s-maxage` cache directives or `x-cache` HIT signals, and rate-limit advertisement headers (`x-ratelimit-*`, `ratelimit-*`, `retry-after`). Score weights: CDN presence 60, useful caching 25, rate-limit headers 15. Toggle via `SCANNER_DOS_POSTURE`.
- This is **not** a load test. Active DoS testing is out of scope (legality, blast radius, distributed-traffic requirements). Use dedicated tools (k6, Locust, gatling) against your own staging environment with explicit authorization for that.

## [0.0.3] - 2026-05-02

### Added
- **Four new scanners**, all free and key-free, raising the default count to nine:
  - **crt.sh (Certificate Transparency)** - surveys the last 90 days of certificates issued for the host. Grades by CA concentration: A+/A for ≤4 CAs, downgrades when many different CAs have signed for the same name (a classic mis-issuance smell). Includes retry-with-backoff for crt.sh's transient 404/5xx errors.
  - **CAA records** (via Cloudflare DNS-over-HTTPS) - verifies the domain pins which CAs may issue certs for it. Walks up the DNS tree to honor CAA inheritance. Decodes both presentation form (`0 issue "letsencrypt.org"`) and the generic `\# <length> <hex>` (RFC 3597) form some resolvers return. A+ when issuance is restricted, C when only iodef is set, D when no records exist.
  - **DNSSEC** (via Cloudflare DoH `AD` flag) - A+ when the resolver returns an authenticated response, F on SERVFAIL (broken chain), D when DNSSEC is simply absent.
  - **HTTP→HTTPS redirect** - calls `http://<host>` directly and walks the redirect chain. A+ for a clean direct redirect to HTTPS on the same host, B if there's an intermediate http hop, C if it crosses to a different host first, F if HTTPS is never reached. Treats "no HTTP listener at all" as A (HTTPS-only is fine).
- Each new scanner has its own `SCANNER_<KEY>=true` toggle in `config.env` (`SCANNER_CRTSH`, `SCANNER_CAA`, `SCANNER_DNSSEC`, `SCANNER_HTTPS_REDIRECT`), all enabled by default.

### Fixed
- **`urlutil.normalize_url`** raised `ValueError` (HTTP 500) when the URL contained an out-of-range port like `:99999`; it now reports a clean form error.

## [0.0.2] - 2026-05-02

### Changed
- **Renamed product to "Url Reporter"**. CLI banner and version output now read `Url Reporter v0.0.2 | Made by Paolo Diomede`. The Python package, CLI command, and repo directory remain `urlreporter`.
- **CLI reports now default to `./reports/<filename>.md`** instead of the current working directory. Pass `--out PATH` to override.

### Added
- **Per-scanner CLI progress** block on stderr that updates in place on a TTY (overwrites previous lines) and falls back to plain output when piped.
- **Per-run error log** at `./logs/error_<YYYYMMDD-HHMMSS>.log`. CLI invocation gets one log file. Scanner errors and unexpected exceptions are written there at WARNING+.
- **`./bin/fix-venv-launcher`**: one-shot helper that patches the pip-generated `urlreporter` console script to inject the project root into `sys.path`. Works around iCloud Drive auto-flagging pip's editable `.pth` files as hidden (Python 3.13+ silently skips hidden `.pth` files).
- **Strict URL validation** (`urlreporter/urlutil.py`): rejects schemes other than http/https (`javascript:`, `data:`, `file:`, `ftp:` …), control characters, embedded credentials, malformed hosts; auto-prepends `https://` when no scheme is present; strips fragment and userinfo; caps URL length at 2000.
- **SSL Labs retries**: transient HTTP responses (429, 500, 502, 503, 504, 521-526, 529) and network errors are retried with exponential backoff (5s, 15s, 30s) before being reported. The retry counter resets between successful poll iterations.

### Fixed
- **`urlutil.normalize_url`** rebuilt IPv6 netlocs without brackets, so `[::1]:8080` became `::1:8080`. Brackets are now preserved when the host contains a colon.
- **`logs/`** added to `.gitignore`.

## [0.0.1] - 2026-05-02

Initial release of **Url Reporter** (`urlreporter`).

### Added
- CLI (`./bin/urlreporter scan <url>`) that runs configured scanners and writes a Markdown report to the current directory.
- Five built-in scanners, all toggleable via `config.env`:
  - SSL Labs (TLS / certificate grade, polling API)
  - Mozilla Observatory v2 (HTTP best-practices score & grade)
  - securityheaders.com (HTTP-headers grade with header-inference fallback when the public `X-Grade` is gated by an API key)
  - internet.nl (link-out - no free single-scan API)
  - hstspreload.org (Chrome HSTS preload status)
- Aggregate overall grade computed across scanners that returned a numeric score; link-out / failed scanners are excluded and noted.
- Prioritized recommendations list deduped by title and sorted by severity.
- Parallel async execution with per-scanner error isolation: one slow or failing scanner does not block the others.
- `config.env` + optional `config.env.local` override; process environment variables override file values.
- macOS / iCloud Drive workaround: bundled `./bin/urlreporter` launcher, `__main__.py`, and `PYTHONPATH=$PWD` instructions for cases where iCloud auto-flags pip's editable `.pth` files as hidden.
- Versioned banner on CLI runs:
  *Url Reporter v0.0.1 | Made by [Paolo Diomede](https://pdiomede.com)*.

### Known limitations
- internet.nl runs as link-out only until an API token is wired in.
- securityheaders.com no longer exposes the letter grade to anonymous clients; the inference fallback only flags missing headers, not relative weight.
