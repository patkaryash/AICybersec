"""API tests: scan resource contract (Phase 2 - creation, NO execution).

Explicitly verifies: 202 creation, queued status, target_snapshot copy,
no tool execution occurs, duplicate active scan 409, cancel contract.
"""
from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from integration.pg import requires_pg

pytestmark = [requires_pg, pytest.mark.usefixtures("clean_db")]

USER_A = {"email": "scan-a@test.example", "password": "password-a-123"}


def _register_and_login(client: TestClient, user: dict) -> dict:
    client.post("/api/v1/auth/register", json=user)
    res = client.post(
        "/api/v1/auth/login", json={"email": user["email"], "password": user["password"]}
    )
    return {"Authorization": f"Bearer {res.json()['data']['access_token']}"}


def _create_project(client: TestClient, headers: dict) -> str:
    res = client.post(
        "/api/v1/projects",
        json={
            "name": "Lab",
            "scope": [{"type": "host", "value": "juice-shop"}, {"type": "cidr", "value": "127.0.0.0/31"}],
        },
        headers=headers,
    )
    assert res.status_code == 201
    return res.json()["data"]["id"]


def _create_scan(client: TestClient, headers: dict, project_id: str, **overrides) -> dict:
    payload = {"project_id": project_id, "profile": "full"}
    payload.update(overrides)
    return client.post("/api/v1/scans", json=payload, headers=headers)


class TestScanCreation:
    def test_create_returns_202_queued(self, client_seeded):
        headers = _register_and_login(client_seeded, USER_A)
        pid = _create_project(client_seeded, headers)
        res = _create_scan(client_seeded, headers, pid)
        assert res.status_code == 202
        body = res.json()
        assert body["success"] is True
        data = body["data"]
        assert data["status"] == "queued"
        assert data["profile"] == "full"
        assert data["mode"] == "pipeline"
        assert data["current_step"] == 0
        assert data["total_steps"] == 3  # full profile: nmap -> httpx -> nuclei
        assert data["findings_count"]["total"] == 0
        assert data["started_at"] is None
        assert data["completed_at"] is None

    def test_target_snapshot_copied_from_project_scope(self, client_seeded):
        headers = _register_and_login(client_seeded, USER_A)
        pid = _create_project(client_seeded, headers)
        res = _create_scan(client_seeded, headers, pid)
        data = res.json()["data"]
        assert data["target_snapshot"] == [
            {"type": "host", "value": "juice-shop", "note": None},
            {"type": "cidr", "value": "127.0.0.0/31", "note": None},
        ]

    def test_snapshot_unchanged_by_later_scope_edit(self, client_seeded):
        headers = _register_and_login(client_seeded, USER_A)
        pid = _create_project(client_seeded, headers)
        scan_id = _create_scan(client_seeded, headers, pid).json()["data"]["id"]
        # change the project scope AFTER scan creation
        client_seeded.patch(
            f"/api/v1/projects/{pid}",
            json={"scope": [{"type": "host", "value": "other-host"}]},
            headers=headers,
        )
        data = client_seeded.get(f"/api/v1/scans/{scan_id}", headers=headers).json()["data"]
        assert data["target_snapshot"][0]["value"] == "juice-shop"

    def test_invalid_profile_422(self, client_seeded):
        headers = _register_and_login(client_seeded, USER_A)
        pid = _create_project(client_seeded, headers)
        res = _create_scan(client_seeded, headers, pid, profile="stealth")
        assert res.status_code == 422

    def test_tool_timeout_bounds(self, client_seeded):
        headers = _register_and_login(client_seeded, USER_A)
        pid = _create_project(client_seeded, headers)
        assert _create_scan(client_seeded, headers, pid, tool_timeout_s=10).status_code == 422
        assert _create_scan(client_seeded, headers, pid, tool_timeout_s=5000).status_code == 422
        assert _create_scan(client_seeded, headers, pid, tool_timeout_s=600).status_code == 202

    def test_duplicate_active_scan_409(self, client_seeded):
        headers = _register_and_login(client_seeded, USER_A)
        pid = _create_project(client_seeded, headers)
        assert _create_scan(client_seeded, headers, pid).status_code == 202
        res = _create_scan(client_seeded, headers, pid)
        assert res.status_code == 409
        body = res.json()
        assert body["error"]["code"] == "SCAN_ALREADY_RUNNING"
        # no PostgreSQL internals leaked
        assert "IntegrityError" not in res.text
        assert "uq_scans_project_active" not in res.text

    def test_unknown_project_404(self, client_seeded):
        headers = _register_and_login(client_seeded, USER_A)
        res = _create_scan(client_seeded, headers, "11111111-2222-3333-4444-555555555555")
        assert res.status_code == 404
        assert res.json()["error"]["code"] == "PROJECT_NOT_FOUND"

class TestScanListAndFilters:
    def test_list_and_filters(self, client_seeded):
        headers = _register_and_login(client_seeded, USER_A)
        pid = _create_project(client_seeded, headers)
        first = _create_scan(client_seeded, headers, pid, profile="recon").json()["data"]["id"]
        # a second ACTIVE scan on the same project is rejected (409);
        # cancel the first to free the slot, then create the second
        assert _create_scan(client_seeded, headers, pid, profile="web").status_code == 409
        client_seeded.post(f"/api/v1/scans/{first}/cancel", headers=headers)
        _create_scan(client_seeded, headers, pid, profile="web")

        res = client_seeded.get("/api/v1/scans", headers=headers)
        assert res.json()["meta"]["total"] == 2

        res = client_seeded.get("/api/v1/scans", params={"status": "cancelled"}, headers=headers)
        items = res.json()["data"]["items"]
        assert len(items) == 1 and items[0]["status"] == "cancelled"

        res = client_seeded.get("/api/v1/scans", params={"status": "queued"}, headers=headers)
        assert all(s["status"] == "queued" for s in res.json()["data"]["items"])

    def test_filter_by_other_users_project_404(self, client_seeded):
        ha = _register_and_login(client_seeded, USER_A)
        hb = {"email": "scan-b@test.example", "password": "password-b-123"}
        _register_and_login(client_seeded, hb)
        # B guesses A's project id in the list filter -> 404, no disclosure
        # (A's project created under A; B cannot see it)
        pid_a = _create_project(client_seeded, ha)
        res = client_seeded.get(
            "/api/v1/scans", params={"project_id": pid_a}, headers={"Authorization": "Bearer " + client_seeded.post(
                "/api/v1/auth/login", json={"email": hb["email"], "password": hb["password"]}
            ).json()["data"]["access_token"]}
        )
        assert res.status_code == 404
        assert res.json()["error"]["code"] == "PROJECT_NOT_FOUND"


class TestScanCancel:
    def test_cancel_queued_202(self, client_seeded):
        headers = _register_and_login(client_seeded, USER_A)
        pid = _create_project(client_seeded, headers)
        scan_id = _create_scan(client_seeded, headers, pid).json()["data"]["id"]
        res = client_seeded.post(f"/api/v1/scans/{scan_id}/cancel", headers=headers)
        assert res.status_code == 202
        data = res.json()["data"]
        assert data["status"] == "cancelled"
        assert data["cancelled_at"] is not None

    def test_cancel_terminal_409(self, client_seeded):
        headers = _register_and_login(client_seeded, USER_A)
        pid = _create_project(client_seeded, headers)
        scan_id = _create_scan(client_seeded, headers, pid).json()["data"]["id"]
        client_seeded.post(f"/api/v1/scans/{scan_id}/cancel", headers=headers)
        res = client_seeded.post(f"/api/v1/scans/{scan_id}/cancel", headers=headers)
        assert res.status_code == 409
        assert res.json()["error"]["code"] == "SCAN_NOT_CANCELLABLE"

    def test_cancel_unknown_scan_404(self, client_seeded):
        headers = _register_and_login(client_seeded, USER_A)
        res = client_seeded.post(
            "/api/v1/scans/11111111-2222-3333-4444-555555555555/cancel", headers=headers
        )
        assert res.status_code == 404
        assert res.json()["error"]["code"] == "SCAN_NOT_FOUND"
