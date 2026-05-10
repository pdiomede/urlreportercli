from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import dotenv_values


@dataclass
class Config:
    enabled: dict[str, bool]
    timeout_seconds: int
    ssl_labs_use_cache: bool
    user_agent: str
    internetnl_api_token: str | None
    stats_hide_hostnames: bool
    source_files: list[Path]


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


_RECOGNIZED_KEYS: tuple[str, ...] = (
    "SCANNER_SSL_LABS",
    "SCANNER_MOZILLA_OBSERVATORY",
    "SCANNER_SECURITY_HEADERS",
    "SCANNER_INTERNETNL",
    "SCANNER_HSTS_PRELOAD",
    "SCANNER_CRTSH",
    "SCANNER_CAA",
    "SCANNER_DNSSEC",
    "SCANNER_HTTPS_REDIRECT",
    "SCANNER_DOS_POSTURE",
    "SCANNER_EMAIL_AUTH",
    "SCANNER_SECURITY_TXT",
    "SCAN_TIMEOUT_SECONDS",
    "SSL_LABS_USE_CACHE",
    "HTTP_USER_AGENT",
    "INTERNETNL_API_TOKEN",
    "STATS_HIDE_HOSTNAMES",
)


def load_config(config_path: Path | None = None) -> Config:
    """Load config.env (and config.env.local override if present).

    Lookup order:
      1. Explicit path passed via --config (highest priority).
      2. ./config.env.local
      3. ./config.env
      4. <package_dir>/../config.env (when run from elsewhere)
    Process environment variables override file values.
    """
    candidates: list[Path] = []
    if config_path is not None:
        candidates.append(config_path)
    cwd = Path.cwd()
    candidates.append(cwd / "config.env.local")
    candidates.append(cwd / "config.env")
    pkg_default = Path(__file__).resolve().parent.parent / "config.env"
    if pkg_default not in candidates:
        candidates.append(pkg_default)

    merged: dict[str, str | None] = {}
    used: list[Path] = []
    # Read in reverse priority so higher-priority entries overwrite.
    for path in reversed(candidates):
        if path.exists() and path.is_file():
            values = dotenv_values(path)
            merged.update(values)
            used.append(path)
    # Process environment overrides everything, even for keys absent from all files.
    for k in _RECOGNIZED_KEYS:
        if k in os.environ:
            merged[k] = os.environ[k]

    enabled = {
        "ssl_labs": _as_bool(merged.get("SCANNER_SSL_LABS"), True),
        "mozilla_observatory": _as_bool(merged.get("SCANNER_MOZILLA_OBSERVATORY"), True),
        "security_headers": _as_bool(merged.get("SCANNER_SECURITY_HEADERS"), True),
        "internetnl": _as_bool(merged.get("SCANNER_INTERNETNL"), True),
        "hsts_preload": _as_bool(merged.get("SCANNER_HSTS_PRELOAD"), True),
        "crtsh": _as_bool(merged.get("SCANNER_CRTSH"), True),
        "caa": _as_bool(merged.get("SCANNER_CAA"), True),
        "dnssec": _as_bool(merged.get("SCANNER_DNSSEC"), True),
        "https_redirect": _as_bool(merged.get("SCANNER_HTTPS_REDIRECT"), True),
        "dos_posture": _as_bool(merged.get("SCANNER_DOS_POSTURE"), True),
        "email_auth": _as_bool(merged.get("SCANNER_EMAIL_AUTH"), True),
        "security_txt": _as_bool(merged.get("SCANNER_SECURITY_TXT"), True),
    }

    try:
        timeout = int(merged.get("SCAN_TIMEOUT_SECONDS") or 180)
    except ValueError:
        timeout = 180
    if timeout < 10:
        timeout = 10

    raw_token = (merged.get("INTERNETNL_API_TOKEN") or "").strip()
    token = raw_token or None

    return Config(
        enabled=enabled,
        timeout_seconds=timeout,
        ssl_labs_use_cache=_as_bool(merged.get("SSL_LABS_USE_CACHE"), True),
        user_agent=merged.get("HTTP_USER_AGENT") or "urlreporter/0.1",
        internetnl_api_token=token,
        stats_hide_hostnames=_as_bool(merged.get("STATS_HIDE_HOSTNAMES"), False),
        source_files=used,
    )
