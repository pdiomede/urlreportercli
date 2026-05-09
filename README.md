# Url Reporter

> Live at **[urlreporter.com](https://urlreporter.com)**. Current version: **v0.0.57**. See [CHANGELOG.md](./CHANGELOG.md) for release notes.

## What it does

Paste a URL and get one report on how exposed the site is, drawn from twelve public security scanners run in parallel. You get:

- a one-screen **summary** (a big letter at the top, top recommendations, per-scanner breakdown), and
- a **detailed report** you can download as either Markdown or a self-contained HTML file.

Two ways to use it:

- **CLI** (`urlreporter scan <url>`): prints the summary to your terminal with a live per-scanner progress block and saves the Markdown report to `./reports/`. Pass `--html` to also save the self-contained HTML report. The Markdown report is written incrementally after every scanner finishes, so a `Ctrl-C` mid-scan still leaves a usable file on disk; the HTML sibling is written at completion or from the latest partial report on interrupt.
- **Web UI** (`./runUrlReporter.sh`): paste a URL, watch a live progress page (real-time bar + per-scanner emoji status table), then read the result page and click either *Download HTML* or *Download Markdown*. Markdown is written to disk after each scanner finishes, so even if the server is killed mid-scan the `.md` file has everything that completed; the heavier self-contained HTML file is written when the scan reaches its final result or error state.

The tool is **passive**: every check either reads a third-party scanner's API or does a single GET to the target. It generates no load, sends no payloads, and requires no authorization to scan any public URL.

## Scanners

By default `urlreporter` queries:

| # | Scanner | What it checks |
|---|---|---|
| 1 | [SSL Labs](https://www.ssllabs.com/ssltest/) | TLS / certificate configuration (letter grade). Polls; can take 1-3 minutes on a cache miss. |
| 2 | [Mozilla Observatory v2](https://developer.mozilla.org/en-US/observatory) | HTTP headers and best practices (score + grade). |
| 3 | [securityheaders.com](https://securityheaders.com/) | HTTP security headers (letter grade). Now sits behind Cloudflare bot protection, so when the third-party probe gets a JS challenge, Url Reporter fetches the target&#39;s headers itself and computes a letter grade locally with a calibrated penalty table. |
| 4 | [internet.nl](https://internet.nl/) | Web standards: TLS, DNSSEC, IPv6, mail. **Link-out** unless an API token is configured (no free single-scan API). |
| 5 | [hstspreload.org](https://hstspreload.org/) | Whether the domain is on the Chrome HSTS preload list. |
| 6 | [crt.sh](https://crt.sh/) + [CertSpotter](https://sslmate.com/certspotter/) | Certificate Transparency: every cert ever issued, graded by CA concentration over the last 90 days. crt.sh is the primary; falls over to CertSpotter (different operator, same CT data) when crt.sh exhausts retries. If both are unreachable, the row degrades to a link-out instead of a red ERROR. |
| 7 | CAA records (via Cloudflare DoH) | DNS-level pin on which CAs may issue certs for the domain (walks up to inherited records). |
| 8 | DNSSEC (via Cloudflare DoH) | Whether the zone is signed and validates to the root (`AD` flag). |
| 9 | HTTP→HTTPS redirect | Calls `http://<host>` and walks the redirect chain; flags missing redirects, intermediate http hops, and cross-host detours. |
| 10 | DoS posture (passive) | Detects CDN/WAF in front, edge-cacheable responses, and rate-limit headers. **Generates no load**; active load testing is out of scope. |
| 11 | Email auth (SPF / DMARC / DKIM) | TXT lookups via Cloudflare DoH for SPF on the apex, DMARC on `_dmarc.<host>`, and DKIM probed across 10 common selectors. Scores by policy strictness (`-all` > `~all` > `+all`; `p=reject` > `p=quarantine` > `p=none`). |
| 12 | security.txt (RFC 9116) | Fetches `/.well-known/security.txt` (then `/security.txt` as legacy fallback), parses it, and grades on canonical-location compliance, `Contact:` presence, and a parseable, future-dated `Expires:` field. |

Failed scanners are isolated: one timing out, erroring, or returning garbage does not stop the others. Every outbound HTTP call retries on transient errors (5xx, 429, network timeouts) before reporting failure. Markdown reports are written incrementally as each scanner finishes, so even if the web server is killed mid-scan the `.md` file on disk reflects everything that completed.

## Architecture

See [ARCHITECTURE.md](./ARCHITECTURE.md) for details on the design, module breakdown, request lifecycle, and file structure.

## Install

```bash
git clone https://github.com/pdiomede/urlreporter.git
cd urlreporter
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .
./bin/fix-venv-launcher    # only needed in iCloud Drive; no-op otherwise
```

Python 3.11+ required (tested on 3.14).

> **macOS / iCloud Drive note.** If your project lives under `~/Library/Mobile Documents/` (iCloud Drive), Apple flags new files as hidden. Python 3.13+ skips hidden `.pth` files, so pip's editable-install console script fails with `ModuleNotFoundError`. Two workarounds ship with the repo:
>
> 1. `./bin/fix-venv-launcher` patches the pip-generated `urlreporter` script so it injects the project path before importing. Run it once after `pip install -e .` and after any reinstall.
> 2. `./bin/urlreporter` is a self-contained launcher that always works (no fix step needed).
>
> Outside iCloud Drive, neither is necessary; the standard `urlreporter` command works directly.

## CLI

```bash
urlreporter scan https://example.com

# equivalent, no install path tricks needed:
./bin/urlreporter scan https://example.com
```

Options:

- `--config PATH`: alternate `config.env`
- `--out PATH`: output filename (default: `./reports/urlreporter-<host>-<timestamp>.md`)
- `--quiet`: suppress the stdout summary and progress display
- `--only ssl_labs,mozilla_observatory`: run only the listed scanners (overrides `config.env`)
- `--html`: also write a self-contained HTML report next to the `.md` file (same renderer the web UI uses)

The CLI also exposes a methodology page equivalent to the web UI's `/score`:

```bash
urlreporter explain-score
```

Markdown reports are written **incrementally** after every scanner finishes, so a Ctrl-C mid-scan or an unexpected engine error still leaves a usable `.md` file on disk with everything that completed. When `--html` is set, the self-contained HTML sibling is written at completion, or from the latest partial report if the CLI exits through its interrupt/error handler.

Exit codes: `0` on success, `1` if every scanner failed (or the engine raised mid-flight), `2` for argument errors, `130` if the scan was interrupted with Ctrl-C (POSIX convention for SIGINT; partial report still on disk).

## Web UI

```bash
./runUrlReporter.sh             # 127.0.0.1:8000
./runUrlReporter.sh 8080        # 127.0.0.1:8080
./runUrlReporter.sh 8080 0.0.0.0  # LAN-visible
CH_RELOAD=1 ./runUrlReporter.sh # uvicorn auto-reload (dev)
```

Then open http://localhost:8000. The web form uses the scanner defaults from `config.env`; for one-off scanner subsets, use the CLI's `--only` option.

## Configuration (`config.env`)

```env
SCANNER_SSL_LABS=true
SCANNER_MOZILLA_OBSERVATORY=true
SCANNER_SECURITY_HEADERS=true
SCANNER_INTERNETNL=true
SCANNER_HSTS_PRELOAD=true
SCANNER_CRTSH=true
SCANNER_CAA=true
SCANNER_DNSSEC=true
SCANNER_HTTPS_REDIRECT=true
SCANNER_DOS_POSTURE=true
SCANNER_EMAIL_AUTH=true
SCANNER_SECURITY_TXT=true

SCAN_TIMEOUT_SECONDS=180
SSL_LABS_USE_CACHE=true
HTTP_USER_AGENT=urlreporter/0.1

INTERNETNL_API_TOKEN=
```

## Logs

Every process run creates `./logs/error_<YYYYMMDD-HHMMSS>.log`. WARNING and above go there: scanner retries (each attempt with the reason), persistent-failure verdicts, unexpected scanner exceptions with full tracebacks, and any callback errors raised inside the runner. The `logs/` directory is gitignored.

## Reports

Generated reports live in `./reports/`. The web app re-writes `<id>.md` (Markdown) after each scanner finishes, then writes `<id>.html` (self-contained HTML, with embedded styles and a print stylesheet) when the scan reaches its final result or error state. A `<id>.name` sibling holds the human-friendly filename used for the download. All three are removed when older than 24 hours.

### Cleanup in production

The in-app `_cleanup_old_reports()` (in `web.py`) runs **once at uvicorn startup** and prunes stale `.md`, `.html`, and `.name` files older than 24h, including orphaned sidecars. That's enough for short-lived processes, but a long-running production uvicorn lets old files accumulate between restarts. The recommended complement is an external scheduler that runs hourly:

```bash
# /usr/local/bin/urlreporter-cleanup
#!/usr/bin/env bash
find /var/www/urlreporter/reports -type f \
  \( -name '*.md' -o -name '*.html' -o -name '*.name' \) \
  -mmin +1440 -delete
```

Wire it to a systemd timer (`urlreporter-cleanup.timer`, `OnUnitActiveSec=1h`) or a `crontab -e` entry (`0 * * * * /usr/local/bin/urlreporter-cleanup`). With either, reports are pruned regardless of the app lifecycle, so disk pressure and stale-file lifespan stay bounded.

## How the overall grade is calculated

Each scanner returns a number from 0 to 100. The overall number is a **weighted** average of every scanner that returned one. Three weight tiers:

- **Weight 2.0** - real cryptographic / authentication posture: SSL Labs, Mozilla Observatory, DNSSEC, Email auth (SPF/DMARC/DKIM).
- **Weight 1.5** - meaningful but narrower: HTTP→HTTPS redirect, securityheaders.com.
- **Weight 1.0** - hardening extras and hygiene markers: CAA, DoS posture, HSTS Preload, security.txt, crt.sh, internet.nl.

Link-out scanners (no public API) and scanners that errored are skipped, and listed separately in the report. The weighted average is rounded to a whole number and mapped to a letter (90 or more is A+, 85 to 89 is A, and so on down to under 35 is F).

The full breakdown, with the letter-to-number table and the honest caveats about the methodology, is on the **`/score`** page (linked from every footer as `OUR SCORE`).

## Adding a scanner

1. Create `urlreporter/scanners/<name>.py` exposing a class with `name`, `config_key`, and `async def scan(self, url, *, client) -> ScanResult`.
2. Wrap every HTTP call with `await retry_request(lambda: client.get(...), label=self.name, logger=log)` from `scanners/_retry.py` so retries and logging come for free.
3. Register it in `urlreporter/scanners/__init__.py` under `REGISTRY`.
4. Add `SCANNER_<KEY>=true` to `config.env` and a default in `config.py`'s `enabled` dict.

## Versioning

Version numbers follow [Semantic Versioning](https://semver.org/). All changes are recorded in [CHANGELOG.md](./CHANGELOG.md).

## Credits

Url Reporter v0.0.57, made by [Paolo Diomede](https://pdiomede.com).

## License

Released under the [MIT License](./LICENSE.md).
