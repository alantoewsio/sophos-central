"""Shared pytest fixtures."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from central.db import init_schema


@pytest.fixture
def tmp_db_path(tmp_path: Path) -> Path:
    return tmp_path / "test.db"


@pytest.fixture
def db_conn(tmp_db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(tmp_db_path)
    conn.row_factory = sqlite3.Row
    init_schema(conn)
    return conn


@pytest.fixture
def mock_response_false() -> MagicMock:
    """Response object that is falsy (covers CentralResponse invalid branch)."""
    m = MagicMock()
    m.__bool__ = lambda self: False
    m.status_code = 0
    m.text = ""
    m.json.side_effect = ValueError()
    return m
