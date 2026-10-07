"""Limits on what a scan will read from the network.

A scan contacts the site it was asked about, and that site decides what to
send back. Without a ceiling, `client.get()` read whatever arrived into
memory: a 300 MB body took one scanner call 0.2 s and the process from 39 MB
to 741 MB, and a server that trickled one byte a second held a scan open
indefinitely, because the read timeout is per chunk rather than per response.
Both let a hostile target cost the server memory and keep scan slots busy.

Two defences live here, both applied to the one `httpx.AsyncClient` every
scanner shares (see `runner.run_scans`):

- `CappedTransport` counts the bytes of every response body as the client
  reads it and aborts past `MAX_RESPONSE_BYTES`. It wraps whichever transport
  actually does the I/O, so tests can put it over an `httpx.MockTransport`.
- The same wrapper drops `Content-Encoding` from redirect responses. httpx
  reads a redirect's body before following it, and decodes it, so a
  compressed body could inflate far beyond the wire cap; nothing ever looks
  at a redirect's body, so it is left as the bytes that arrived.

The cap counts bytes on the wire, before decompression. The scanners that
fetch the target itself therefore either never read the body (they want the
headers and the final URL: `dos_posture`, `security_headers`,
`https_redirect`) or read it in bounded pieces (`security_txt`). Third-party
APIs are read whole, bounded by the cap.

The per-scanner deadline that pairs with this lives in `runner._safe_scan`.
"""
from __future__ import annotations

from collections.abc import AsyncIterator

import httpx

# Generous for every legitimate answer: the largest honest response a scan
# reads is a crt.sh listing for a busy domain, well under this, and the
# direct-target scanners read only headers or a few KiB. Small enough that
# every in-flight scan together cannot exhaust memory.
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class ResponseTooLarge(httpx.HTTPError):
    """The response body passed `MAX_RESPONSE_BYTES` and reading stopped.

    An `HTTPError` rather than a `RequestError` on purpose: `retry_request`
    retries request errors, and a body this size would arrive again on every
    attempt. Scanners already catch `httpx.HTTPError` and report it as a
    normal scanner failure.
    """

    def __init__(self, limit: int, url: str) -> None:
        super().__init__(
            f"Response from {url} exceeded {limit // (1024 * 1024)} MiB; "
            "stopped reading it."
        )


class _CappedStream(httpx.AsyncByteStream):
    def __init__(self, inner: httpx.AsyncByteStream, limit: int, url: str) -> None:
        self._inner = inner
        self._limit = limit
        self._url = url

    async def __aiter__(self) -> AsyncIterator[bytes]:
        seen = 0
        async for chunk in self._inner:
            seen += len(chunk)
            if seen > self._limit:
                raise ResponseTooLarge(self._limit, self._url)
            yield chunk

    async def aclose(self) -> None:
        await self._inner.aclose()


class CappedTransport(httpx.AsyncBaseTransport):
    """An async transport that bounds every response body it hands back."""

    def __init__(
        self,
        inner: httpx.AsyncBaseTransport | None = None,
        *,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
    ) -> None:
        self._inner = inner if inner is not None else httpx.AsyncHTTPTransport()
        self._max = max_response_bytes

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self._inner.handle_async_request(request)
        if response.is_redirect:
            # Read raw, never decoded: see the module docstring.
            response.headers.pop("content-encoding", None)
        if isinstance(response.stream, httpx.AsyncByteStream):
            response.stream = _CappedStream(response.stream, self._max, str(request.url))
        return response

    async def aclose(self) -> None:
        await self._inner.aclose()

    async def __aenter__(self) -> CappedTransport:
        await self._inner.__aenter__()
        return self

    async def __aexit__(self, *args: object) -> None:
        await self._inner.__aexit__(*args)


async def fetch_headers(
    client: httpx.AsyncClient, url: str, **kwargs: object
) -> httpx.Response:
    """GET `url` for its status, headers, history and final URL, reading no body.

    For the scanners that look only at how the site answers. The connection
    is closed as soon as the headers are in, so a body of any size, or one
    that never ends, costs nothing. Redirects are followed as `client.get`
    would follow them, and the SSRF hook runs for each hop as before.
    """
    request = client.build_request("GET", url, **kwargs)  # type: ignore[arg-type]
    response = await client.send(request, stream=True, follow_redirects=True)
    await response.aclose()
    return response


async def read_body(response: httpx.Response, limit: int) -> bytes:
    """Up to `limit` bytes of a streamed response's decoded body, then stop.

    `response.text` would read the whole thing. Reading in chunks bounds what
    a compressed body can inflate to as well: each chunk is decoded on its
    own, and the loop stops at the first that takes the total past `limit`.
    """
    parts: list[bytes] = []
    seen = 0
    try:
        async for chunk in response.aiter_bytes():
            parts.append(chunk)
            seen += len(chunk)
            if seen >= limit:
                break
    finally:
        await response.aclose()
    return b"".join(parts)[:limit]
