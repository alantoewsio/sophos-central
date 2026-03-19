"""Tests for central.logging_config."""

from __future__ import annotations

import logging
from pathlib import Path

from central.logging_config import configure_logging


def _clear_root_handlers():
    root = logging.getLogger()
    for h in root.handlers[:]:
        root.removeHandler(h)


def test_configure_logging_creates_file_and_level(tmp_path: Path):
    log_file = tmp_path / "sub" / "app.log"
    _clear_root_handlers()
    configure_logging(level="DEBUG", log_file=str(log_file))
    assert log_file.parent.is_dir()
    assert log_file.exists()
    logging.getLogger("central.test").debug("x")
    assert log_file.stat().st_size > 0


def test_configure_logging_int_level(tmp_path: Path):
    log_file = tmp_path / "a.log"
    _clear_root_handlers()
    configure_logging(level=logging.WARNING, log_file=str(log_file))
    assert logging.getLogger().level == logging.WARNING


def test_configure_logging_duplicate_same_file_skips_second_handler(tmp_path: Path):
    lf = tmp_path / "one.log"
    _clear_root_handlers()
    configure_logging(level="INFO", log_file=str(lf))
    n = len(logging.getLogger().handlers)
    configure_logging(level="INFO", log_file=str(lf))
    assert len(logging.getLogger().handlers) == n


def test_configure_logging_invalid_level_string_defaults_info(tmp_path: Path):
    log_file = tmp_path / "b.log"
    _clear_root_handlers()
    configure_logging(level="NOT_A_LEVEL", log_file=str(log_file))
    assert logging.getLogger().level == logging.INFO


def test_configure_logging_env_level(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "ERROR")
    log_file = tmp_path / "c.log"
    _clear_root_handlers()
    configure_logging(log_file=str(log_file))
    assert logging.getLogger().level == logging.ERROR
