"""Pytest configuration: fresh isolated runtime directory for each test session."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest


@pytest.fixture()
def runs_dir(tmp_path: Path) -> Path:
    """Temporary per-test directory for state/trajectory files."""
    return tmp_path / "runs"


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Isolated environment: AICYBERSEC_RUNS_DIR pointed at a temp directory."""
    monkeypatch.setenv("AICYBERSEC_RUNS_DIR", str(tmp_path / "runs"))
    for var in ("AICYBERSEC_ALLOWED_TARGETS", "AICYBERSEC_MAX_STEPS", "AICYBERSEC_MAX_DANGER"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """FastAPI TestClient with isolated runs dir and a fresh RunManager."""
    monkeypatch.setenv("AICYBERSEC_RUNS_DIR", str(tmp_path / "runs"))
    from agent_core.config import get_settings

    get_settings.cache_clear()

    import backend.deps as deps

    deps._manager = None  # reset the composition-root singleton per test

    from fastapi.testclient import TestClient

    from backend.main import create_app

    with TestClient(create_app()) as test_client:
        yield test_client

    deps._manager = None
    get_settings.cache_clear()
