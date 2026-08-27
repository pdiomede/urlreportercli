# Url Reporter

> Current version: **v1.0.4**. See [CHANGELOG.md](./CHANGELOG.md) for release notes.

A command-line tool that aggregates twelve public security scanners into one report for any URL.

## What it does

Point it at a URL and get one report on how exposed the site is, drawn from twelve public security
scanners run in parallel. You get:

- a one-screen **summary** printed to your terminal (a big letter at the top, top recommendations,
  per-scanner breakdown), and
- a **detailed report** saved to disk as Markdown, or as a self-contained HTML file with `--html`.

```bash
urlreporter scan https://example.com
```

While the scan runs, a live per-scanner progress block is drawn on stderr (updated in place on a
TTY, plain lines when piped). The Markdown report is written **incrementally** after every scanner
finishes, so a `Ctrl-C` mid-scan still leaves a usable file on disk; the HTML sibling is written at
completion, or from the latest partial report on interrupt.

The tool is **passive**: every check either reads a third-party scanner's API or does a single GET
to the target. It generates no load, sends no payloads, and requires no authorization to scan any
public URL.

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

Failed scanners are isolated: one timing out, erroring, or returning garbage does not stop the
others. Every outbound HTTP call retries on transient errors (5xx, 429, network timeouts) before
reporting failure. Markdown reports are written incrementally as each scanner finishes, so even if
the process is interrupted mid-scan the `.md` file on disk reflects everything that completed.

## Install

```bash
git clone https://github.com/pdiomede/urlreportercli.git
cd urlreportercli
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

## Usage

```bash
urlreporter scan https://example.com

# equivalent, no install path tricks needed:
./bin/urlreporter scan https://example.com
```

The URL is normalized before anything runs: `https://` is prepended when no scheme is given, and
`javascript:` / `data:` / `file:` / `ftp:` schemes, control characters, embedded credentials,
malformed hosts, and out-of-range ports are rejected outright.

Options for `scan`:

- `--config PATH`: alternate `config.env`
- `--out PATH`: output filename (default: `./reports/urlreporter-<host>-<timestamp>.md`)
- `--quiet`: suppress the stdout summary and progress display
- `--only ssl_labs,mozilla_observatory`: run only the listed scanners (overrides `config.env`)
- `--html`: also write a self-contained HTML report next to the `.md` file

Two more commands:

```bash
urlreporter explain-score   # plain-English walkthrough of how the overall grade is calculated
urlreporter --version
```

Exit codes: `0` on success, `1` if every scanner failed (or the engine raised mid-flight), `2` for
argument errors, `130` if the scan was interrupted with Ctrl-C (POSIX convention for SIGINT; partial
report still on disk).

## Reports

Reports are written to `./reports/` by default, named
`urlreporter-<host>-<timestamp>.md`. Pass `--out PATH` to choose a different location; the parent
directory is created if it does not exist. With `--html`, a self-contained HTML file (embedded
styles plus a print stylesheet, so it prints or exports to PDF cleanly) is written alongside the
`.md` with the same basename.

The `.md` file is re-rendered after every scanner finishes, so it is always current with whatever
has completed. The `.html` sibling is rendered once at the end — full inline-CSS HTML is too
expensive to rewrite on every scanner, and nothing reads it mid-scan.

Nothing prunes `./reports/` automatically: the directory is gitignored and grows until you clean it
up.

## How it works

1. **`urlutil.normalize_url()`** validates and canonicalizes the input URL — the single gate every
   scan passes through.
2. **`config.load_config()`** merges the package defaults, `config.env`, `config.env.local`, and the
   process environment (in that order of increasing priority) into a `Config` describing which
   scanners are enabled and the tunables.
3. **`runner.run_scans()`** instantiates every enabled scanner from `scanners/__init__.py:REGISTRY`
   and runs them concurrently under one shared `httpx.AsyncClient`, emitting progress events as it
   goes. Each scanner is wrapped so an exception becomes a failed `ScanResult` rather than
   cancelling its siblings. Every outbound request goes through `scanners/_retry.py:retry_request`,
   which backs off on transient errors (3s / 8s / 20s) and logs each attempt.
4. **`grading.aggregate_score()`** converts letters to numbers and takes a weighted mean over the
   scanners that returned one, then maps the result back to a letter.
5. **`report.py`** renders three ways from the same data: `render_summary()` for the terminal,
   `render_markdown()` for the `.md` file, `render_html()` for the self-contained HTML document.
6. **`logging_setup.setup_logger()`** attaches one file handler per process so retries, failures,
   and tracebacks land in `./logs/`.

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

Booleans accept `1` / `true` / `yes` / `on`. Copy `config.env.example` to `config.env.local` for
personal overrides and tokens — it is gitignored and takes priority over `config.env`.

## Logs

Every process run creates `./logs/error_<YYYYMMDD-HHMMSS>.log`. WARNING and above go there: scanner
retries (each attempt with the reason), persistent-failure verdicts, unexpected scanner exceptions
with full tracebacks, and any callback errors raised inside the runner. The `logs/` directory is
gitignored.

## How the overall grade is calculated

Each scanner returns a number from 0 to 100. The overall number is a **weighted** average of every
scanner that returned one. Three weight tiers:

- **Weight 2.0** - real cryptographic / authentication posture: SSL Labs, Mozilla Observatory, DNSSEC, Email auth (SPF/DMARC/DKIM).
- **Weight 1.5** - meaningful but narrower: HTTP→HTTPS redirect, securityheaders.com.
- **Weight 1.0** - hardening extras and hygiene markers: CAA, DoS posture, HSTS Preload, security.txt, crt.sh, internet.nl.

Link-out scanners (no public API) and scanners that errored are skipped, and listed separately in
the report. The weighted average is rounded to a whole number and mapped to a letter (90 or more is
A+, 85 to 89 is A, and so on down to under 35 is F).

For the full breakdown — the letter-to-number table, the weight tiers, and the honest caveats about
the methodology — run:

```bash
urlreporter explain-score
```

## Adding a scanner

1. Create `urlreporter/scanners/<name>.py` exposing a class with `name`, `config_key`, and `async def scan(self, url, *, client) -> ScanResult`.
2. Wrap every HTTP call with `await retry_request(lambda: client.get(...), label=self.name, logger=log)` from `scanners/_retry.py` so retries and logging come for free.
3. Register it in `urlreporter/scanners/__init__.py` under `REGISTRY`.
4. Add `SCANNER_<KEY>=true` to `config.env` and a default in `config.py`'s `enabled` dict.

## Versioning

Version numbers follow [Semantic Versioning](https://semver.org/). All changes are recorded in [CHANGELOG.md](./CHANGELOG.md).

## Credits

Url Reporter v1.0.4, made by [Paolo Diomede](https://pdiomede.com).

## License

Released under the [MIT License](./LICENSE.md).
