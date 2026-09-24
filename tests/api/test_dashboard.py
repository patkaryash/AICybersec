"""API tests: the single dashboard endpoint."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from integration.pg import requires_pg

pytestmark = [requires_pg, pytest.mark.usefixtures("clean_db")]

USER_A = {"email": "dash-a@test.example", "password": "password-a-123"}


def _register_and_login(client: TestClient, user: dict) -> dict:
    client.post("/api/v1/auth/register", json=user)
    res = client.post(
        "/api/v1/auth/login", json={"email": user["email"], "password": user["password"]}
    )
    return {"Authorization": f"Bearer {res.json()['data']['access_token']}"}


def test_dashboard_requires_auth(client_seeded):
    res = client_seeded.get("/api/v1/dashboard")
    assert res.status_code == 401
    assert res.json()["error"]["code"] == "INVALID_CREDENTIALS"


def test_dashboard_empty_state(client_seeded):
    headers = _register_and_login(client_seeded, USER_A)
    res = client_seeded.get("/api/v1/dashboard", headers=headers)
    assert res.status_code == 200
    body = res.json()
    assert body["success"] is True
    data = body["data"]
    assert data["total_projects"] == 0
    assert data["total_scans"] == 0
    assert data["running_scans"] == 0
    assert data["total_findings"] == 0
    assert data["total_assets"] == 0
    assert data["scans_by_status"]["queued"] == 0
    assert data["findings_by_severity"]["critical"] == 0
    assert data["recent_scans"] == []


def test_dashboard_aggregates_and_recent_scans(client_seeded):
    headers = _register_and_login(client_seeded, USER_A)
    pid = client_seeded.post(
        "/api/v1/projects",
        json={"name": "Lab", "scope": [{"type": "host", "value": "juice-shop"}]},
        headers=headers,
    ).json()["data"]["id"]
    client_seeded.post(
        "/api/v1/scans", json={"project_id": pid, "profile": "full"}, headers=headers
    )
    res = client_seeded.get("/api/v1/dashboard", headers=headers)
    data = res.json()["data"]
    assert data["total_projects"] == 1
    assert data["total_scans"] == 1
    assert data["scans_by_status"]["queued"] == 1
    assert len(data["recent_scans"]) == 1
    assert data["recent_scans"][0]["status"] == "queued"
    assert data["recent_scans"][0]["findings_count"]["total"] == 0


def test_dashboard_ownership(client_seeded):
    ha = _register_and_login(client_seeded, USER_A)
    hb = {"email": "dash-b@test.example", "password": "password-b-123"}
    headers_b = _register_and_login(client_seeded, hb)
    client_seeded.post(
        "/api/v1/projects",
        json={"name": "B-project", "scope": [{"type": "host", "value": "b.local"}]},
        headers=headers_b,
    )
    data_a = client_seeded.get("/api/v1/dashboard", headers=ha).json()["data"]
    assert data_a["total_projects"] == 0  # B's project invisible to A
    data_b = client_seeded.get("/api/v1/dashboard", headers=headers_b).json()["data"]
    assert data_b["total_projects"] == 1


def test_dashboard_admin_sees_all(client_seeded):
    headers = _register_and_login(client_seeded, USER_A)
    client_seeded.post(
        "/api/v1/projects",
        json={"name": "A-project", "scope": [{"type": "host", "value": "a.local"}]},
        headers=headers,
    )
    res = client_seeded.post(
        "/api/v1/auth/login",
        json={"email": "admin@aicybersec.dev", "password": "admin-dev-password-change-me"},
    )
    admin_headers = {"Authorization": f"Bearer {res.json()['data']['access_token']}"}
    data = client_seeded.get("/api/v1/dashboard", headers=admin_headers).json()["data"]
    assert data["total_projects"] == 1


def test_dashboard_recent_limit_param(client_seeded):
    headers = _register_and_login(client_seeded, USER_A)
    pid = client_seeded.post(
        "/api/v1/projects",
        json={"name": "Lab", "scope": [{"type": "host", "value": "juice-shop"}]},
        headers=headers,
    ).json()["data"]["id"]
    # one active scan at a time: cancel each to free the slot
    for i in range(3):
        scan_id = client_seeded.post(
            "/api/v1/scans", json={"project_id": pid, "profile": "recon"}, headers=headers
        ).json()["data"]["id"]
        if i < 2:
            client_seeded.post(f"/api/v1/scans/{scan_id}/cancel", headers=headers)
    res = client_seeded.get(
        "/api/v1/dashboard", params={"recent_limit": 2}, headers=headers
    )
    assert res.status_code == 200
    assert len(res.json()["data"]["recent_scans"]) == 2
