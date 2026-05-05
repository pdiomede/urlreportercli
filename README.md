# Url Reporter (CLI)

> Current version: **v0.0.45**. See [CHANGELOG.md](./CHANGELOG.md) for release notes.

CLI tool that runs a URL through twelve public security scanners in parallel and writes a consolidated report to disk. Passive only: every check either reads a third-party scanner's API or does a single GET to the target.

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

Options:

- `--config PATH`: alternate `config.env`
- `--out PATH`: output filename (default: `./reports/urlreporter-<host>-<timestamp>.md`)
- `--quiet`: suppress the stdout summary and progress display
- `--only ssl_labs,mozilla_observatory`: run only the listed scanners (overrides `config.env`)
- `--html`: also write a self-contained HTML report next to the `.md` file

The CLI also exposes the methodology used for the overall grade:

```bash
urlreporter explain-score
```

Reports are written **incrementally** after every scanner finishes, so a `Ctrl-C` mid-scan or an unexpected engine error still leaves a usable file on disk with everything that completed.

Exit codes: `0` on success, `1` if every scanner failed (or the engine raised mid-flight), `2` for argument errors, `130` if the scan was interrupted with Ctrl-C.

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

Personal overrides and tokens belong in `config.env.local` (gitignored).

## Logs

Every run creates `./logs/error_<YYYYMMDD-HHMMSS>.log`. WARNING and above go there: scanner retries (each attempt with the reason), persistent-failure verdicts, and unexpected scanner exceptions with full tracebacks. The `logs/` directory is gitignored.

## Reports

Generated reports live in `./reports/`. After each scanner finishes, the report is rewritten on disk in Markdown (and HTML if `--html`). Reports are not auto-pruned by the CLI; clean up `./reports/` manually as needed.

## Credits

Url Reporter v0.0.45, made by [Paolo Diomede](https://pdiomede.com).

## License

Released under the [MIT License](./LICENSE.md).
