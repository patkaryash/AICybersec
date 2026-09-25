"""CONTROLLED-LAB end-to-end scan test (Phase 3 §38).

MARKER-GATED: ``lab_e2e``. Normal unit/integration runs DESELECT this
test (see pyproject addopts ``-m "not lab_e2e"``); run it explicitly:

    pytest -m lab_e2e

Requires a REAL lab target (OWASP Juice Shop via
``docker compose --profile lab up``) and nmap on the host/container.
NEVER scans public websites or uncontrolled systems - the project scope
is created from the configured lab target only.

Flow: create project (scope = lab target) -> POST /scans -> 202 queued ->
initializing -> running -> real Nmap -> XML parse -> assets persisted ->
ToolRuns persisted -> events persisted -> completed.
"""
from __future__ import annotations

import os
import socket
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient

from backend.main import create_app

pytestmark = [pytest.mark.lab_e2e]

E2E_TARGET = os.getenv("AICYBERSEC_E2E_TARGET", "http://127.0.0.1:3000")


def _lab_target_reachable() -> bool:
    try:
        parsed = urlparse(E2E_TARGET)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        with socket.create_connection((host, port), timeout=3):
            return True
    except OSError:
        return False


@pytest.fixture(scope="module")
def e2e_client():
    """TestClient against the real lab stack (real DB, real tools)."""
    with TestClient(create_app()) as client:
        yield client


def _auth(client: TestClient) -> dict:
    import uuid

    payload = {
        "email": f"e2e-{uuid.uuid4().hex[:8]}@test.example",
        "password": "e2e-password-123",
    }
    client.post("/api/v1/auth/register", json=payload)
    res = client.post("/api/v1/auth/login", json=payload)
    assert res.status_code == 200
    return {"Authorization": f"Bearer {res.json()['data']['access_token']}"}


@pytest.mark.skipif(
    not _lab_target_reachable(),
    reason=f"Lab target {E2E_TARGET} not reachable (docker compose --profile lab up)",
)
def test_nmap_vertical_slice(e2e_client):
    headers = _auth(e2e_client)

    # 1. create project with the LAB TARGET in scope (never arbitrary)
    res = e2e_client.post(
        "/api/v1/projects",
        json={"name": "Lab E2E", "scope": [{"type": "url", "value": E2E_TARGET}]},
        headers=headers,
    )
    assert res.status_code == 201
    pid = res.json()["data"]["id"]

    # 2. create scan -> 202 queued
    res = e2e_client.post(
        "/api/v1/scans", json={"project_id": pid, "profile": "recon"}, headers=headers
    )
    assert res.status_code == 202
    scan_id = res.json()["data"]["id"]
    assert res.json()["data"]["status"] == "queued"

    # 3. wait for the real scan to reach a terminal state (a real nmap
    #    scan takes tens of seconds; the deadline is generous)
    import time

    deadline = time.time() + 600
    final = None
    while time.time() < deadline:
        snap = e2e_client.get(f"/api/v1/scans/{scan_id}", headers=headers).json()["data"]
        if snap["status"] in ("completed", "failed", "cancelled"):
            final = snap
            break
        time.sleep(2)
    assert final is not None, "scan did not reach a terminal state in 600s"

    # 4. the scan completed with REAL results (no fake data)
    assert final["status"] == "completed"

    # 5. tool runs persisted with audit data (argv populated by the runner)
    runs = e2e_client.get(f"/api/v1/scans/{scan_id}/tool-runs", headers=headers).json()["data"]["items"]
    assert len(runs) >= 1
    assert any(r["tool"] == "nmap" for r in runs)
    # the API excludes internal audit fields
    assert all("argv" not in r and "raw_output" not in r for r in runs)

    # 6. assets persisted from the REAL nmap XML
    assets = e2e_client.get(f"/api/v1/scans/{scan_id}/assets", headers=headers).json()["data"]["items"]
    assert len(assets) >= 1

    # 7. lifecycle events persisted in the frozen snake_case vocabulary
    events = e2e_client.get(
        f"/api/v1/scans/{scan_id}/agent-events?after_id=0&limit=100", headers=headers
    ).json()["data"]["items"]
    types = [e["event_type"] for e in events]
    assert "scan_started" in types
    assert "tool_started" in types
    assert types[-1] in ("scan_completed", "scan_failed")

    # 8. the DNS bridge authorized the resolved IP (host/url entries +
    #    forward-DNS resolutions) - verified implicitly by the scan
    #    completing with httpx accepted against the resolved target.
