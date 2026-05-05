from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Protocol

import httpx

Severity = Literal["critical", "high", "medium", "low", "info"]

SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


@dataclass
class Finding:
    severity: Severity
    title: str
    detail: str = ""
    recommendation: str | None = None


@dataclass
class ScanResult:
    scanner: str
    ok: bool
    grade: str | None = None
    score: int | None = None
    summary: str = ""
    findings: list[Finding] = field(default_factory=list)
    link: str = ""
    error: str | None = None


class Scanner(Protocol):
    name: str
    config_key: str

    async def scan(self, url: str, *, client: httpx.AsyncClient) -> ScanResult: ...
