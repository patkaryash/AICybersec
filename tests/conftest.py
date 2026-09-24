"""Pytest configuration: fresh isolated runtime directory for each test session."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest


def reset_caches() -> None:
    """Clear cached settings/engines so per-test env changes take effect.

    Covers agent_core settings and the backend settings/engine/session
    caches (see backend/db/session.py).
    """
    from agent_core.config import get_settings

    get_settings.cache_clear()

    import backend.db.session as db_session

    db_session.get_engine.cache_clear()
    db_session.get_session_factory.cache_clear()

    from backend.core.config import get_backend_settings

    get_backend_settings.cache_clear()


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
    """FastAPI TestClient with isolated runs dir and a fresh RunManager.

    The admin seed is disabled (empty admin email) so tests that do not
    need a database never attempt a DB connection at startup; DB tests
    use the client_seeded fixture instead.
    """
    monkeypatch.setenv("AICYBERSEC_RUNS_DIR", str(tmp_path / "runs"))
    monkeypatch.setenv("AICYBERSEC_ADMIN_EMAIL", "")
    from agent_core.config import get_settings

    get_settings.cache_clear()

    import backend.deps as deps

    deps._manager = None  # reset the composition-root singleton per test

    reset_caches()

    from fastapi.testclient import TestClient

    from backend.main import create_app

    with TestClient(create_app()) as test_client:
        yield test_client

    deps._manager = None
    reset_caches()


@pytest.fixture()
def client_seeded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """FastAPI TestClient with the admin seed enabled (DB tests only)."""
    monkeypatch.setenv("AICYBERSEC_RUNS_DIR", str(tmp_path / "runs"))
    monkeypatch.setenv("AICYBERSEC_ADMIN_EMAIL", "admin@aicybersec.local")
    monkeypatch.setenv("AICYBERSEC_ADMIN_PASSWORD", "admin-dev-password-change-me")
    from agent_core.config import get_settings

    get_settings.cache_clear()

    import backend.deps as deps

    deps._manager = None

    reset_caches()

    from fastapi.testclient import TestClient

    from backend.main import create_app

    with TestClient(create_app()) as test_client:
        yield test_client

    deps._manager = None
    reset_caches()
