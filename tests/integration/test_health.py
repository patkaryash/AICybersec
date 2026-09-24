"""Integration tests: health + readiness endpoints.

Health/liveness runs anywhere. Readiness against a guaranteed-unreachable
database must return the 503 DATABASE_ERROR envelope; readiness against a
live PostgreSQL (skipped when none is reachable) returns 200.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from integration.pg import requires_pg


def test_health_envelope(client):
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    body = res.json()
    assert body["success"] is True
    assert body["data"]["status"] == "ok"
    assert body["error"] is None
    assert body["meta"]["request_id"]


def test_ready_with_unreachable_db(tmp_path, monkeypatch):
    """A dead database must surface as a clean 503 envelope, not a crash."""
    from agent_core.config import get_settings

    monkeypatch.setenv("AICYBERSEC_RUNS_DIR", str(tmp_path / "runs"))
    monkeypatch.setenv("AICYBERSEC_ADMIN_EMAIL", "")  # skip the admin seed
    monkeypatch.setenv(
        "AICYBERSEC_DATABASE_URL",
        "postgresql+psycopg://aicybersec:aicybersec@127.0.0.1:1/none?connect_timeout=2",
    )
    get_settings.cache_clear()

    import backend.deps as deps

    deps._manager = None

    from backend.core.config import get_backend_settings
    import backend.db.session as db_session

    get_backend_settings.cache_clear()
    db_session.get_engine.cache_clear()
    db_session.get_session_factory.cache_clear()

    from backend.main import create_app

    try:
        with TestClient(create_app()) as c:
            res = c.get("/api/v1/health/ready")
        assert res.status_code == 503
        body = res.json()
        assert body["success"] is False
        assert body["error"]["code"] == "DATABASE_ERROR"
        assert body["meta"]["request_id"]
    finally:
        deps._manager = None
        get_backend_settings.cache_clear()
        db_session.get_engine.cache_clear()
        db_session.get_session_factory.cache_clear()


@requires_pg
def test_ready_ok(client_seeded):
    res = client_seeded.get("/api/v1/health/ready")
    assert res.status_code == 200
    assert res.json()["data"]["status"] == "ready"


@requires_pg
def test_admin_seeded_on_startup(client_seeded):
    from sqlalchemy import select

    from backend.core.config import get_backend_settings
    from backend.db.models import User
    from backend.db.session import get_session_factory

    settings = get_backend_settings()
    with get_session_factory().begin() as session:
        admin = session.scalar(
            select(User).where(User.email == settings.admin_email.lower())
        )
    assert admin is not None
    assert admin.role == "admin"
    assert admin.password_hash.startswith("$argon2")
