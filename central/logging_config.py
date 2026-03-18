"""
Centralized logging configuration for the Sophos Central app.
Provides DEBUG, INFO, WARNING, and ERROR with file output.
"""
from __future__ import annotations

import logging
import os

# Default log directory (project root / logs)
_LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
_LOG_FILE = os.path.join(_LOGS_DIR, "sophos_central.log")

_FORMAT = "%(asctime)s | %(levelname)-5s | %(name)s | %(message)s"
_DATE_FMT = "%Y-%m-%d %H:%M:%S"


def configure_logging(
    level: str | int | None = None,
    log_file: str | None = None,
) -> None:
    """
    Configure application logging with a file handler.
    Call once at application startup (e.g. from main.py).

    Args:
        level: Log level name or int (e.g. 'DEBUG', logging.DEBUG).
               Defaults to env LOG_LEVEL or 'INFO'.
        log_file: Path to log file. Defaults to logs/sophos_central.log.
    """
    log_level = level or os.environ.get("LOG_LEVEL", "INFO")
    if isinstance(log_level, str):
        log_level = getattr(logging, log_level.upper(), logging.INFO)

    path = log_file or _LOG_FILE
    log_dir = os.path.dirname(path)
    if log_dir and not os.path.isdir(log_dir):
        os.makedirs(log_dir, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(log_level)

    # Avoid duplicate handlers if called more than once
    if not any(isinstance(h, logging.FileHandler) and getattr(h, "baseFilename", "").endswith(os.path.basename(path)) for h in root.handlers):
        fh = logging.FileHandler(path, encoding="utf-8")
        fh.setLevel(log_level)
        fh.setFormatter(logging.Formatter(_FORMAT, datefmt=_DATE_FMT))
        root.addHandler(fh)

    # Ensure our package loggers propagate and use root level
    for name in ("central", "main"):
        logging.getLogger(name).setLevel(log_level)
