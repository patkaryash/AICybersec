"""Pytest configuration: fresh isolated runtime directory for each test session."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest


def reset_caches() -> None:
    """Clear cached settings/engines so per-test env changes take effect.

    Covers agent_core settings, the backend settings/engine/session
    caches (see backend/db/session.py), and the ScanManager singleton
    (its pool/registry hold per-process state).
    """
    from agent_core.config import get_settings

    get_settings.cache_clear()

    import backend.db.session as db_session

    db_session.get_engine.cache_clear()
    db_session.get_session_factory.cache_clear()

    import backend.services.scan_manager as scan_manager_module

    scan_manager_module._manager = None

    from backend.core.config import get_backend_settings

    get_backend_settings.cache_clear()


# Model selection must never leak from the developer's shell into tests:
# the normal suite runs mock/scripted only (M3-C hermeticity rule).
_MODEL_ENV_VARS = (
    "AICYBERSEC_MODEL_PROVIDER",
    "AICYBERSEC_MODEL_BASE_URL",
    "AICYBERSEC_MODEL_API_KEY",
    "AICYBERSEC_MODEL_NAME",
)


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
    for var in _MODEL_ENV_VARS:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture(scope="session")
def pg_engine():
    """Session-scoped engine on the configured database (DB tests only)."""
    from backend.db.session import get_engine

    return get_engine()


@pytest.fixture()
def clean_db(pg_engine):
    """Truncate all platform tables between DB-backed tests.

    DB tests share one PostgreSQL database; without this, registrations,
    scans and dashboard totals would accumulate across tests and break
    exact-count assertions.
    """
    from sqlalchemy import text

    from backend.db import models  # noqa: F401  (registers tables on metadata)
    from backend.db.base import Base

    names = [t.name for t in Base.metadata.sorted_tables]
    statement = "TRUNCATE TABLE " + ", ".join(f'"{n}"' for n in names) + " RESTART IDENTITY CASCADE"
    with pg_engine.begin() as conn:
        conn.execute(text(statement))


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """FastAPI TestClient with isolated runs dir and a fresh RunManager.

    The admin seed is disabled (empty admin email) so tests that do not
    need a database never attempt a DB connection at startup; DB tests
    use the client_seeded fixture instead.
    """
    monkeypatch.setenv("AICYBERSEC_RUNS_DIR", str(tmp_path / "runs"))
    monkeypatch.setenv("AICYBERSEC_ADMIN_EMAIL", "")
    # Phase 3: scans must NOT auto-execute in the shared fixtures -
    # background workers would make count/status assertions racy.
    # Execution tests opt in explicitly (own fixture or direct submit).
    monkeypatch.setenv("AICYBERSEC_SCAN_AUTO_START", "0")
    for var in _MODEL_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
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
def client_seeded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clean_db):
    """FastAPI TestClient with the admin seed enabled (DB tests only).

    Depends on clean_db so truncation always happens BEFORE app startup
    (the lifespan seed then re-creates the admin user on a clean DB).
    """
    monkeypatch.setenv("AICYBERSEC_RUNS_DIR", str(tmp_path / "runs"))
    monkeypatch.setenv("AICYBERSEC_ADMIN_EMAIL", "admin@aicybersec.dev")
    monkeypatch.setenv("AICYBERSEC_ADMIN_PASSWORD", "admin-dev-password-change-me")
    monkeypatch.setenv("AICYBERSEC_SCAN_AUTO_START", "0")
    for var in _MODEL_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
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
