from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

LOG_DIR_NAME = "logs"
PACKAGE_LOGGER = "urlreporter"


@dataclass
class _LogState:
    path: Path | None = None
    handlers: list[logging.Handler] = field(default_factory=list)


_state = _LogState()


def setup_logger(label: str = "default") -> tuple[logging.Logger, Path]:
    """Configure a process-wide file logger at ./logs/error_<ts>.log.

    Attaches the file handler to the *package* logger ('urlreporter'), so
    every submodule logger (`urlreporter.runner`, `urlreporter.scanners.*`,
    etc.) propagates here automatically without having to be re-configured.

    Idempotent across calls within one process: the second call returns the
    same logger and same path. The `label` argument is kept for backward
    compatibility but no longer affects the file name; one process gets one
    log file.
    """
    pkg = logging.getLogger(PACKAGE_LOGGER)

    if _state.path is not None:
        return pkg, _state.path

    logs_dir = Path.cwd() / LOG_DIR_NAME
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = logs_dir / f"error_{ts}.log"

    pkg.setLevel(logging.DEBUG)
    pkg.propagate = False  # don't bubble to root (avoids duplicate stderr noise)

    handler = logging.FileHandler(log_path, encoding="utf-8", delay=True)
    handler.setLevel(logging.WARNING)
    handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    pkg.addHandler(handler)
    _state.handlers.append(handler)
    _state.path = log_path
    return pkg, log_path
