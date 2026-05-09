from __future__ import annotations

import asyncio
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import click

from . import APP_NAME, AUTHOR_URL, __version__, credit_line
from .config import load_config
from .grading import aggregate_score
from .logging_setup import setup_logger
from .report import render_html, render_markdown, render_summary
from .runner import Report, _prioritize, run_scans
from .scanners import REGISTRY
from .urlutil import InvalidURL, normalize_url


def _safe_filename(host: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", host) or "host"


SCORE_EXPLANATION = """\
How the overall grade is calculated
===================================

The big letter at the top of every report is a summary of the per-scanner
table, not a single official rating. Each scanner gives a grade or score.
This tool turns every grade into a number, skips scanners that could not
return one, and takes a weighted average of the rest.

How letter grades become numbers
--------------------------------
Some scanners return a number directly. Others return a letter. The
letter ones convert via this fixed table:

    A+ = 100   B+ = 85    C+ = 70    D+ = 55    E       = 40
    A  =  95   B  = 80    C  = 65    D  = 50    F/T/M   =  0
    A- =  90   B- = 75    C- = 60    D- = 45

How scanners are combined
-------------------------
A weighted mean of every scanner that returned a number. Scanners that
measure real cryptographic or authentication posture count for more
than optional hygiene markers:

    Weight 2.0   SSL Labs, Mozilla Observatory, DNSSEC,
                 Email auth (SPF/DMARC/DKIM)
    Weight 1.5   HTTP→HTTPS redirect, securityheaders.com
    Weight 1.0   CAA, DoS posture, HSTS Preload, security.txt,
                 crt.sh, internet.nl

Two kinds are skipped:
  * Link-out scanners (no public API; e.g. internet.nl when no token).
  * Failed scanners (timeout, malformed response, rate-limit).

When no scanner returned a number, the report says
"No graded scanners returned a score." rather than invent a letter.

How the average becomes the letter
----------------------------------
Round the weighted average to the nearest whole number, then read this
ladder:

    90 or more  = A+    65 to 69    = B-    40 to 44    = D
    85 to 89    = A     60 to 64    = C+    35 to 39    = D-
    80 to 84    = A-    55 to 59    = C     under 35    = F
    75 to 79    = B+    50 to 54    = C-
    70 to 74    = B     45 to 49    = D+

Caveats
-------
  * Scanner weights are a judgment call. They reflect what we think
    moves the needle on real-world security posture; reasonable people
    can disagree.
  * Different scanners measure different things. An A+ from one is not
    the same as an A+ from another.
  * Link-out scanners do not pull the average down; they are simply
    absent from it.
  * It is a snapshot. Run the same scan tomorrow and the letter can
    move: third-party rate-limits, site changes, expired certs.
  * It is our number, not theirs. None of the third-party scanners has
    endorsed it.
"""


@click.group()
@click.version_option(version=__version__, prog_name=APP_NAME)
def main() -> None:
    """urlreporter - aggregate public security scanners for a URL."""


class _ProgressPrinter:
    """Renders a per-scanner progress block on stderr.

    Layout (one line per scanner, stable order):
      [ ] SSL Labs              waiting…
      [-] Mozilla Observatory   running…  3.4s
      [✓] HSTS Preload          done       0.4s   D (40)
      [x] securityheaders.com   error      1.1s   No X-Grade header

    On terminals (isatty) the block is updated in place using ANSI cursor
    moves. On non-terminals (pipes, file redirects) each event prints a
    plain line.
    """

    DONE = "✓"
    ERR = "x"
    RUN = "-"
    WAIT = " "

    def __init__(self, stream) -> None:
        self.stream = stream
        self.tty = bool(getattr(stream, "isatty", lambda: False)())
        self._order: list[str] = []
        self._state: dict[str, dict] = {}
        self._started = time.monotonic()
        self._lines_drawn = 0

    def __call__(self, event: dict) -> None:
        et = event.get("type")
        if et == "start":
            self._order = list(event.get("scanners") or [])
            self._state = {n: {"status": "waiting"} for n in self._order}
            self._render(initial=True)
        elif et == "scanner_start":
            name = event["scanner"]
            if name not in self._state:
                self._order.append(name)
                self._state[name] = {}
            self._state[name]["status"] = "running"
            self._state[name]["started"] = time.monotonic()
            self._render()
        elif et == "scanner_done":
            name = event["scanner"]
            self._state.setdefault(name, {})
            self._state[name]["status"] = "done" if event.get("ok") else "error"
            self._state[name]["elapsed"] = event.get("elapsed")
            self._state[name]["grade"] = event.get("grade")
            self._state[name]["score"] = event.get("score")
            self._state[name]["error"] = event.get("error")
            self._render()
        elif et == "done":
            self._render(final=True)

    def _format_line(self, name: str) -> str:
        s = self._state.get(name, {})
        status = s.get("status", "waiting")
        marker = {
            "waiting": self.WAIT,
            "running": self.RUN,
            "done": self.DONE,
            "error": self.ERR,
        }.get(status, "?")

        if status == "running":
            elapsed = time.monotonic() - s.get("started", self._started)
            tail = f"running… {elapsed:>5.1f}s"
        elif status == "done":
            elapsed = s.get("elapsed") or 0.0
            grade = s.get("grade")
            score = s.get("score")
            bits = []
            if grade is not None:
                bits.append(grade)
            if score is not None:
                bits.append(f"{score}/100")
            extra = "  " + " · ".join(bits) if bits else "  link-out (no public API)"
            tail = f"done   {elapsed:>5.1f}s{extra}"
        elif status == "error":
            elapsed = s.get("elapsed") or 0.0
            err = (s.get("error") or "").split("\n", 1)[0][:60]
            tail = f"ERROR  {elapsed:>5.1f}s  {err}"
        else:
            tail = "waiting…"

        return f"  [{marker}] {name:<22} {tail}"

    def _render(self, initial: bool = False, final: bool = False) -> None:
        lines = [self._format_line(n) for n in self._order]
        if self.tty and self._lines_drawn:
            # Move cursor up to overwrite previous block.
            self.stream.write(f"\x1b[{self._lines_drawn}A")
        for line in lines:
            self.stream.write("\x1b[2K" if self.tty else "")
            self.stream.write(line + "\n")
        self._lines_drawn = len(lines) if self.tty else 0
        self.stream.flush()


class _IncrementalWriter:
    """Persists a partial Report after every scanner_done event so a
    Ctrl-C / kill / engine exception mid-scan still leaves a usable
    report file on disk. Mirrors web._write_partial_report()."""

    def __init__(self, *, url: str, md_path: Path,
                 cfg_files: list[str], log_path: str | None = None) -> None:
        self.url = url
        self.md_path = md_path
        self.cfg_files = cfg_files
        self.log_path = log_path
        self._scanner_order: list[str] = []
        self._partial_results: list = []
        self._registration = None
        self.last_report: Report | None = None

    def __call__(self, event: dict) -> None:
        et = event.get("type")
        if et == "start":
            self._scanner_order = list(event.get("scanners") or [])
        elif et == "scanner_done":
            r = event.get("result")
            if r is not None:
                self._partial_results.append(r)
                self._flush()
        elif et == "registration":
            # The registration event arrives after every scanner completes
            # but before 'done'. Capturing it here means an interrupt or
            # engine failure that lands between this event and 'done' still
            # leaves a partial report on disk that includes the registration
            # section.
            self._registration = event.get("registration")
            self._flush()
        elif et == "done":
            self._flush()

    def _flush(self) -> None:
        # Mirror runner.py's stable scanner-registration ordering so the
        # on-disk report doesn't reshuffle as scanners finish in different
        # orders on each run.
        order = {n: i for i, n in enumerate(self._scanner_order)}
        results = sorted(self._partial_results, key=lambda r: order.get(r.scanner, 999))
        score, grade = aggregate_score(results)
        report = Report(
            url=self.url,
            generated_at=datetime.now(timezone.utc),
            overall_score=score,
            overall_grade=grade,
            results=results,
            recommendations=_prioritize(results),
            config_files=self.cfg_files,
            registration=self._registration,
        )
        try:
            self.md_path.parent.mkdir(parents=True, exist_ok=True)
            self.md_path.write_text(render_markdown(report, log_path=self.log_path), encoding="utf-8")
            # HTML is rendered once at the end by the CLI main loop (using
            # writer.last_report on the interrupt path). Re-rendering the
            # full inline-CSS HTML after every scanner is wasted work;
            # nobody reads the partial HTML mid-scan.
            self.last_report = report
        except OSError:
            # Disk error mid-scan must not sink the live scan; the runner
            # is still going and we'll try again on the next event.
            pass


def _composite_handler(*handlers):
    def emit(event: dict) -> None:
        for h in handlers:
            if h is None:
                continue
            h(event)
    return emit


@main.command()
@click.argument("url")
@click.option("--config", "config_path", type=click.Path(path_type=Path), default=None,
              help="Path to a config.env file (defaults to ./config.env.local then ./config.env).")
@click.option("--out", "out_path", type=click.Path(path_type=Path), default=None,
              help="Where to write the markdown report (defaults to ./reports/<auto-filename>.md).")
@click.option("--quiet", is_flag=True, help="Suppress the stdout summary and progress display.")
@click.option("--only", default=None,
              help="Comma-separated scanner keys to enable (overrides config). "
                   f"Valid keys: {', '.join(REGISTRY.keys())}")
@click.option("--html", "html_flag", is_flag=True, default=False,
              help="Also write a self-contained HTML report next to the .md file.")
def scan(url: str, config_path: Path | None, out_path: Path | None, quiet: bool,
         only: str | None, html_flag: bool) -> None:
    """Scan URL across the configured public security scanners."""
    try:
        target = normalize_url(url)
    except InvalidURL as e:
        click.echo(f"Invalid URL: {e}", err=True)
        sys.exit(2)
    cfg = load_config(config_path)
    logger, log_path = setup_logger("cli")

    if only:
        wanted = {k.strip() for k in only.split(",") if k.strip()}
        unknown = wanted - set(REGISTRY.keys())
        if unknown:
            click.echo(f"Unknown scanner key(s): {', '.join(sorted(unknown))}", err=True)
            sys.exit(2)
        cfg.enabled = {k: (k in wanted) for k in REGISTRY.keys()}

    if not any(cfg.enabled.values()):
        click.echo("No scanners enabled. Edit config.env or pass --only.", err=True)
        sys.exit(2)

    if not quiet:
        click.echo(f"{credit_line()} ({AUTHOR_URL})", err=True)
        click.echo(f"Scanning {target}…", err=True)
        active = [k for k, v in cfg.enabled.items() if v]
        click.echo(f"Active scanners: {', '.join(active)}", err=True)
        click.echo(f"Errors will be logged to: {log_path}", err=True)
        click.echo("", err=True)

    host = urlparse(target).hostname or "host"
    if out_path is None:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        out_path = Path.cwd() / "reports" / f"urlreporter-{_safe_filename(host)}-{ts}.md"
    html_path = out_path.with_suffix(".html") if html_flag else None
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        click.echo(f"Failed to create report directory: {e}", err=True)
        sys.exit(1)

    progress = None if quiet else _ProgressPrinter(sys.stderr)
    writer = _IncrementalWriter(
        url=target,
        md_path=out_path,
        cfg_files=[str(p) for p in cfg.source_files],
        log_path=str(log_path) if log_path else None,
    )
    handler = _composite_handler(progress, writer)

    interrupted = False
    error_msg: str | None = None
    report: Report | None = None
    try:
        report = asyncio.run(run_scans(target, cfg, on_event=handler, logger=logger))
    except KeyboardInterrupt:
        interrupted = True
        logger.warning("CLI scan interrupted by user")
    except Exception as e:  # noqa: BLE001 - preserve partial output on any engine failure
        error_msg = f"{type(e).__name__}: {e}"
        logger.exception("CLI scan failed mid-flight")

    # On success, the runner-returned Report is authoritative (sorted +
    # full recommendations). On failure / interrupt, fall back to the
    # incremental writer's last good partial.
    if report is None:
        report = writer.last_report

    write_failed = False
    if report is not None:
        try:
            out_path.write_text(render_markdown(report, log_path=str(log_path)), encoding="utf-8")
            if html_path is not None:
                html_path.write_text(render_html(report, log_path=str(log_path)), encoding="utf-8")
        except OSError as e:
            write_failed = True
            click.echo(f"Failed to write report: {e}", err=True)

    if not quiet and report is not None:
        click.echo("")
        click.echo(render_summary(report, log_path=str(log_path)))
        click.echo("")

    if interrupted:
        if report is not None and not write_failed:
            click.echo(f"Scan interrupted. Partial report written to: {out_path}", err=True)
            if html_path is not None:
                click.echo(f"Partial HTML report written to: {html_path}", err=True)
        elif report is not None:
            click.echo("Scan interrupted, but the partial report could not be written.", err=True)
        else:
            click.echo("Scan interrupted before any scanner finished. No report written.", err=True)
        sys.exit(130)

    if error_msg is not None:
        click.echo(f"Scan failed: {error_msg}", err=True)
        if report is not None and not write_failed:
            click.echo(f"Partial report written to: {out_path}", err=True)
            if html_path is not None:
                click.echo(f"Partial HTML report written to: {html_path}", err=True)
        elif report is not None:
            click.echo("A partial report was produced, but it could not be written.", err=True)
        sys.exit(1)

    if report is None:
        click.echo("Scan produced no report.", err=True)
        sys.exit(1)

    if write_failed:
        sys.exit(1)

    click.echo(f"Report written to: {out_path}")
    if html_path is not None:
        click.echo(f"HTML report written to: {html_path}")

    all_failed = report.results and all(not r.ok for r in report.results)
    sys.exit(1 if all_failed else 0)


@main.command("explain-score")
def explain_score() -> None:
    """Print, in plain English, how the overall grade is calculated."""
    click.echo(SCORE_EXPLANATION)


if __name__ == "__main__":
    main()
