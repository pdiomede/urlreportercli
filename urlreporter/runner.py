from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Awaitable, Callable

import httpx

from .config import Config
from .grading import aggregate_score
from .scanners import REGISTRY
from .scanners._retry import describe_exc
from .scanners.base import Finding, ScanResult, SEVERITY_ORDER

ProgressCallback = Callable[[dict], Awaitable[None] | None]


@dataclass
class Report:
    url: str
    generated_at: datetime
    overall_score: int | None
    overall_grade: str
    results: list[ScanResult]
    recommendations: list[tuple[Finding, str]] = field(default_factory=list)
    config_files: list[str] = field(default_factory=list)
    total_elapsed: float | None = None


def _build_scanners(cfg: Config) -> list:
    scanners = []
    for key, cls in REGISTRY.items():
        if not cfg.enabled.get(key, False):
            continue
        if key == "ssl_labs":
            scanners.append(cls(use_cache=cfg.ssl_labs_use_cache, timeout_seconds=cfg.timeout_seconds))
        elif key == "internetnl":
            scanners.append(cls(api_token=cfg.internetnl_api_token))
        else:
            scanners.append(cls())
    return scanners


async def _safe_scan(scanner, url: str, client: httpx.AsyncClient,
                     logger: logging.Logger | None) -> ScanResult:
    try:
        return await scanner.scan(url, client=client)
    except asyncio.CancelledError:
        raise
    except Exception as e:  # noqa: BLE001 - error isolation is the whole point here
        if logger is not None:
            logger.exception("Scanner '%s' raised an unexpected exception", getattr(scanner, "name", "?"))
        return ScanResult(
            scanner=getattr(scanner, "name", scanner.__class__.__name__),
            ok=False,
            error=describe_exc(e),
        )


async def _emit(cb: ProgressCallback | None, event: dict, logger: logging.Logger | None = None) -> None:
    """Invoke a progress callback, swallowing its own errors so a buggy
    listener can never sink a scan."""
    if cb is None:
        return
    try:
        rv = cb(event)
        if asyncio.iscoroutine(rv):
            await rv
    except Exception as e:  # noqa: BLE001
        if logger is not None:
            logger.warning("on_event callback raised: %s", describe_exc(e))


async def run_scans(
    url: str,
    cfg: Config,
    *,
    on_event: ProgressCallback | None = None,
    logger: logging.Logger | None = None,
) -> Report:
    """Run all enabled scanners in parallel.

    `on_event` is invoked (sync or async) with dict events:
      - {"type": "start", "scanners": [name, ...], "total": N}
      - {"type": "scanner_start", "scanner": name}
      - {"type": "scanner_done", "scanner": name, "ok": bool, "grade": str|None,
         "score": int|None, "elapsed": float, "completed": k, "total": N,
         "error": str|None}
      - {"type": "done", "total": N}
    """
    scanners = _build_scanners(cfg)
    total = len(scanners)
    run_started = time.monotonic()
    await _emit(on_event, logger=logger, event={"type": "start", "scanners": [s.name for s in scanners], "total": total})

    if not scanners:
        await _emit(on_event, logger=logger, event={"type": "done", "total": 0})
        return Report(
            url=url,
            generated_at=datetime.now(timezone.utc),
            overall_score=None,
            overall_grade="?",
            results=[],
            config_files=[str(p) for p in cfg.source_files],
            total_elapsed=round(time.monotonic() - run_started, 1),
        )

    # Use cfg.timeout_seconds as the read timeout (capped to a sensible
    # window) so the user-tunable knob actually affects every scanner, not
    # just SSL Labs polling.
    read_timeout = float(min(max(cfg.timeout_seconds, 30), 300))
    timeout = httpx.Timeout(connect=10.0, read=read_timeout, write=30.0, pool=30.0)
    headers = {"User-Agent": cfg.user_agent}
    results: list[ScanResult] = []

    async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
        starts: dict[asyncio.Task, tuple[str, float]] = {}
        for s in scanners:
            await _emit(on_event, logger=logger, event={"type": "scanner_start", "scanner": s.name})
            t = asyncio.create_task(_safe_scan(s, url, client, logger))
            starts[t] = (s.name, time.monotonic())

        # Use asyncio.wait(FIRST_COMPLETED) instead of as_completed: the
        # latter yields wrapper coroutines, not the original Task objects,
        # so any per-task bookkeeping keyed by task identity (like our
        # `starts` map) silently breaks.
        completed = 0
        pending: set[asyncio.Task] = set(starts.keys())
        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                result = task.result()
                completed += 1
                results.append(result)
                elapsed = time.monotonic() - starts[task][1]
                if not result.ok and logger is not None:
                    logger.error(
                        "Scanner '%s' failed on %s: %s",
                        result.scanner, url, result.error,
                    )
                await _emit(on_event, logger=logger, event={
                    "type": "scanner_done",
                    "scanner": result.scanner,
                    "ok": result.ok,
                    "grade": result.grade,
                    "score": result.score,
                    "elapsed": round(elapsed, 1),
                    "completed": completed,
                    "total": total,
                    "error": result.error,
                    "link": result.link,
                    "summary": result.summary,
                    # Pass the full dataclass so listeners can persist partial
                    # state (e.g. write a partial markdown report after each
                    # scanner finishes, so a server crash mid-scan still
                    # yields a downloadable report of what completed).
                    "result": result,
                })

    # Re-order results to match the original scanner order so reports stay stable.
    name_order = {s.name: i for i, s in enumerate(scanners)}
    results.sort(key=lambda r: name_order.get(r.scanner, 999))

    overall_score, overall_grade = aggregate_score(results)
    recommendations = _prioritize(results)

    await _emit(on_event, logger=logger, event={"type": "done", "total": total})

    return Report(
        url=url,
        generated_at=datetime.now(timezone.utc),
        overall_score=overall_score,
        overall_grade=overall_grade,
        results=results,
        recommendations=recommendations,
        config_files=[str(p) for p in cfg.source_files],
        total_elapsed=round(time.monotonic() - run_started, 1),
    )


def _prioritize(results: list[ScanResult]) -> list[tuple[Finding, str]]:
    """Flatten findings, sort by severity then scanner, dedupe by lowercased title."""
    flat: list[tuple[Finding, str]] = []
    for r in results:
        for f in r.findings:
            flat.append((f, r.scanner))

    seen: set[str] = set()
    unique: list[tuple[Finding, str]] = []
    for f, scanner in flat:
        key = f.title.strip().lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append((f, scanner))

    unique.sort(key=lambda pair: (SEVERITY_ORDER.get(pair[0].severity, 99), pair[1]))
    return unique
