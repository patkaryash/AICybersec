"""Integration tests: Phase 3 scan execution (PostgreSQL-gated).

Covers the router auto-submit path end to end: POST /scans submits the
run, the worker executes real tools (binaries absent in CI, so tools
fail fast and deterministically), and terminal state plus persisted
events/tool-runs are observable through the API.

The shared client fixtures keep AUTO_START=0; execution tests use the
local client_exec fixture (AUTO_START=1).
"""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from integration.pg import requires_pg

pytestmark = [requires_pg, pytest.mark.usefixtures("clean_db")]

USER = {"email": "exec@test.example", "password": "password-123"}


def _reset_caches():
    from agent_core.config import get_settings

    get_settings.cache_clear()
    import backend.db.session as db_session

    db_session.get_engine.cache_clear()
    db_session.get_session_factory.cache_clear()
    from backend.core.config import get_backend_settings

    get_backend_settings.cache_clear()


@pytest.fixture()
def client_exec(tmp_path, monkeypatch):
    """TestClient with scan auto-submit enabled (execution tests only)."""
    monkeypatch.setenv("AICYBERSEC_RUNS_DIR", str(tmp_path / "runs"))
    monkeypatch.setenv("AICYBERSEC_ADMIN_EMAIL", "")
    monkeypatch.setenv("AICYBERSEC_SCAN_AUTO_START", "1")
    for var in (
        "AICYBERSEC_ALLOWED_TARGETS",
        "AICYBERSEC_MAX_STEPS",
        "AICYBERSEC_MAX_DANGER",
        "AICYBERSEC_MODEL_PROVIDER",
        "AICYBERSEC_MODEL_BASE_URL",
        "AICYBERSEC_MODEL_API_KEY",
        "AICYBERSEC_MODEL_NAME",
    ):
        monkeypatch.delenv(var, raising=False)
    from agent_core.config import get_settings

    get_settings.cache_clear()
    _reset_caches()
    from backend.main import create_app

    with TestClient(create_app()) as test_client:
        yield test_client
    _reset_caches()


def _auth(client):
    client.post("/api/v1/auth/register", json=USER)
    res = client.post("/api/v1/auth/login", json=USER)
    assert res.status_code == 200
    return {"Authorization": f"Bearer {res.json()['data']['access_token']}"}


def _project(client, headers):
    res = client.post(
        "/api/v1/projects",
        json={"name": "Lab", "scope": [{"type": "host", "value": "demo.local"}]},
        headers=headers,
    )
    assert res.status_code == 201
    return res.json()["data"]["id"]


def _wait_terminal(client, headers, scan_id, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        data = client.get(f"/api/v1/scans/{scan_id}", headers=headers).json()["data"]
        if data["status"] in ("completed", "failed", "cancelled"):
            return data
        time.sleep(0.2)
    raise AssertionError(f"scan {scan_id} did not reach a terminal state in time")


def test_auto_submit_runs_to_terminal_and_persists(client_exec):
    headers = _auth(client_exec)
    pid = _project(client_exec, headers)
    res = client_exec.post(
        "/api/v1/scans", json={"project_id": pid, "profile": "recon"}, headers=headers
    )
    assert res.status_code == 202
    scan_id = res.json()["data"]["id"]
    final = _wait_terminal(client_exec, headers, scan_id)
    # Real tools with absent binaries fail fast and deterministically.
    assert final["status"] == "completed"
    events = client_exec.get(
        f"/api/v1/scans/{scan_id}/agent-events?after_id=0&limit=100", headers=headers
    ).json()["data"]["items"]
    types = [e["event_type"] for e in events]
    # Phase 3 §29: persisted events use the frozen snake_case vocabulary;
    # scan lifecycle events are emitted by the executor, per-step runtime
    # events are translated by the db_sink (dot-notation never persisted).
    assert "scan_started" in types
    # Offline reality: absent binaries fail deterministically -> tool_failed
    # (tool_completed is covered by the db_sink translation unit tests).
    assert "tool_started" in types and "tool_failed" in types
    assert types[-1] == "scan_completed"
    # Reasoning never reaches the database.
    assert "reasoning" not in client_exec.get(
        f"/api/v1/scans/{scan_id}/agent-events?after_id=0&limit=100", headers=headers
    ).text
    runs = client_exec.get(
        f"/api/v1/scans/{scan_id}/tool-runs", headers=headers
    ).json()["data"]["items"]
    assert {r["tool"] for r in runs} == {"nmap", "httpx"}
    assert all(r["status"] in ("completed", "failed", "timeout") for r in runs)
    # Response contract excludes internal audit fields.
    assert all("argv" not in r and "raw_output" not in r for r in runs)


def test_auto_start_disabled_stays_queued(client):
    """Shared fixture keeps AUTO_START=0: no worker, no rows, deterministic."""
    res = client.post("/api/v1/auth/register", json=USER)
    assert res.status_code == 201
    token = client.post("/api/v1/auth/login", json=USER).json()["data"]["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    pid = _project(client, headers)
    scan_id = client.post(
        "/api/v1/scans", json={"project_id": pid, "profile": "recon"}, headers=headers
    ).json()["data"]["id"]
    time.sleep(2)
    data = client.get(f"/api/v1/scans/{scan_id}", headers=headers).json()["data"]
    assert data["status"] == "queued"
    runs = client.get(f"/api/v1/scans/{scan_id}/tool-runs", headers=headers).json()["data"]
    assert runs["items"] == []


def test_cancel_running_scan_via_service():
    """Service-level running -> cancelling (no thread needed)."""
    from backend.db.models import Project, Scan, User
    from backend.db.session import get_session_factory
    from backend.services import scan_service

    factory = get_session_factory()
    with factory() as session:
        user = User(email="c@test.example", password_hash="x", role="user")
        session.add(user)
        session.flush()
        project = Project(owner_id=user.id, name="P", scope=[])
        session.add(project)
        session.flush()
        scan = Scan(
            project_id=project.id, status="running", mode="pipeline", profile="recon",
            target_snapshot=[], tool_timeout_s=60,
        )
        session.add(scan)
        session.commit()
        transient = User(id=user.id, email=user.email, role="user", is_active=True)
        out = scan_service.cancel_scan(session, user=transient, scan_id=scan.id)
        assert out.status == "cancelling"
        session.refresh(scan)
        assert scan.status == "cancelling"
