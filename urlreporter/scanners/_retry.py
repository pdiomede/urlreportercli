from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable

import httpx

# HTTP statuses considered transient and worth retrying. We deliberately
# include 404 because some upstreams (crt.sh under load) return 404 for valid
# queries until their cache warms; same for 408 (request timeout).
TRANSIENT_STATUSES = frozenset({
    404, 408, 429, 500, 502, 503, 504,
    520, 521, 522, 523, 524, 525, 526, 527, 529,  # Cloudflare-style
})

DEFAULT_BACKOFFS: tuple[float, ...] = (3.0, 8.0, 20.0)


class RetryExhausted(httpx.HTTPError):
    """Raised when retry_request runs out of attempts."""

    def __init__(self, message: str, *, status_code: int | None = None,
                 last_exception: BaseException | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.last_exception = last_exception


def _format_exc(exc: BaseException) -> str:
    s = str(exc)
    return f"{type(exc).__name__}: {s}" if s else type(exc).__name__


async def retry_request(
    fn: Callable[[], Awaitable[httpx.Response]],
    *,
    label: str,
    backoffs: tuple[float, ...] | list[float] | None = None,
    transient_statuses: frozenset[int] | set[int] = TRANSIENT_STATUSES,
    logger: logging.Logger | None = None,
    treat_404_as_transient: bool = False,
) -> httpx.Response:
    """Run `fn` with retries on transient HTTP/network failures.

    `fn` is a zero-arg coroutine factory that performs one HTTP request and
    returns the `httpx.Response`. On a 2xx/3xx/4xx-non-transient response we
    return immediately. On transient statuses or `httpx.RequestError` (network
    timeouts, connection failures, DNS errors) we sleep and retry, up to
    `len(backoffs)` extra attempts.

    Raises `RetryExhausted` after the final attempt, with `last_exception`
    populated when the failures were network-level. Non-transient HTTP
    statuses are returned to the caller for them to raise/handle.
    """
    bos = list(backoffs if backoffs is not None else DEFAULT_BACKOFFS)
    if not treat_404_as_transient:
        transient_statuses = transient_statuses - {404}
    last_exc: BaseException | None = None
    last_status: int | None = None
    attempts = len(bos) + 1

    for i in range(attempts):
        if i > 0:
            delay = bos[i - 1]
            if logger is not None:
                logger.warning(
                    "%s: retrying after %.1fs (attempt %d/%d, last: %s)",
                    label, delay, i + 1, attempts,
                    f"HTTP {last_status}" if last_status is not None else _format_exc(last_exc) if last_exc else "?",
                )
            await asyncio.sleep(delay)
        try:
            resp = await fn()
        except httpx.RequestError as e:
            last_exc = e
            last_status = None
            if logger is not None:
                logger.warning("%s: network error %s", label, _format_exc(e))
            continue
        if resp.status_code in transient_statuses:
            last_status = resp.status_code
            last_exc = None
            if logger is not None:
                logger.warning("%s: transient HTTP %d", label, resp.status_code)
            continue
        return resp

    msg = f"{label}: gave up after {attempts} attempts"
    if last_status is not None:
        msg += f"; last HTTP {last_status}"
    if last_exc is not None:
        msg += f"; last error {_format_exc(last_exc)}"
    raise RetryExhausted(msg, status_code=last_status, last_exception=last_exc)


def describe_exc(exc: BaseException) -> str:
    """Human-readable error string that never produces empty output.

    `httpx.HTTPStatusError` and friends sometimes have empty `__str__`, so
    we always fall back to the type name."""
    return _format_exc(exc)
