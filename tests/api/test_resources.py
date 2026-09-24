"""API tests: findings / assets / agent-events / tool-runs read contracts.

Phase 2 has no scanner execution, so normal scans return empty items;
the read contracts (authorization, pagination, error envelopes) are what
matters. Includes the no-execution contract assertion.
"""
from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from integration.pg import requires_pg

pytestmark = [requires_pg, pytest.mark.usefixtures("clean_db")]

USER_A = {"email": "res-a@test.example", "password": "password-a-123"}


def _register_and_login(client: TestClient, user: dict) -> dict:
    client.post("/api/v1/auth/register", json=user)
    res = client.post(
        "/api/v1/auth/login", json={"email": user["email"], "password": user["password"]}
    )
    return {"Authorization": f"Bearer {res.json()['data']['access_token']}"}


def _create_scan(client: TestClient, headers: dict) -> str:
    pid = client.post(
        "/api/v1/projects",
        json={"name": "Lab", "scope": [{"type": "host", "value": "juice-shop"}]},
        headers=headers,
    ).json()["data"]["id"]
    res = client.post("/api/v1/scans", json={"project_id": pid, "profile": "full"}, headers=headers)
    assert res.status_code == 202
    return res.json()["data"]["id"]


class TestResourceReadContracts:
    def test_findings_empty_for_new_scan(self, client_seeded):
        headers = _register_and_login(client_seeded, USER_A)
        scan_id = _create_scan(client_seeded, headers)
        res = client_seeded.get(f"/api/v1/scans/{scan_id}/findings", headers=headers)
        assert res.status_code == 200
        body = res.json()
        assert body["success"] is True
        assert body["data"]["items"] == []
        assert body["meta"]["page"] == 1

    def test_assets_empty_for_new_scan(self, client_seeded):
        headers = _register_and_login(client_seeded, USER_A)
        scan_id = _create_scan(client_seeded, headers)
        res = client_seeded.get(f"/api/v1/scans/{scan_id}/assets", headers=headers)
        assert res.status_code == 200
        assert res.json()["data"]["items"] == []

    def test_agent_events_empty_for_new_scan(self, client_seeded):
        headers = _register_and_login(client_seeded, USER_A)
        scan_id = _create_scan(client_seeded, headers)
        res = client_seeded.get(f"/api/v1/scans/{scan_id}/agent-events", headers=headers)
        assert res.status_code == 200
        assert res.json()["data"]["items"] == []

    def test_tool_runs_empty_for_new_scan(self, client_seeded):
        headers = _register_and_login(client_seeded, USER_A)
        scan_id = _create_scan(client_seeded, headers)
        res = client_seeded.get(f"/api/v1/scans/{scan_id}/tool-runs", headers=headers)
        assert res.status_code == 200
        assert res.json()["data"]["items"] == []

    def test_no_execution_occurs(self, client_seeded):
        """Phase 2 contract: creating a scan persists the record only -
        no tool runs, assets, agent events or findings exist afterwards."""
        headers = _register_and_login(client_seeded, USER_A)
        scan_id = _create_scan(client_seeded, headers)
        for path in (
            f"/api/v1/scans/{scan_id}/tool-runs",
            f"/api/v1/scans/{scan_id}/assets",
            f"/api/v1/scans/{scan_id}/agent-events",
            f"/api/v1/scans/{scan_id}/findings",
        ):
            res = client_seeded.get(path, headers=headers)
            assert res.status_code == 200, path
            assert res.json()["data"]["items"] == [], path

    def test_unknown_scan_404(self, client_seeded):
        headers = _register_and_login(client_seeded, USER_A)
        for path in (
            "/api/v1/scans/11111111-2222-3333-4444-555555555555/findings",
            "/api/v1/scans/11111111-2222-3333-4444-555555555555/assets",
            "/api/v1/scans/11111111-2222-3333-4444-555555555555/agent-events",
            "/api/v1/scans/11111111-2222-3333-4444-555555555555/tool-runs",
        ):
            res = client_seeded.get(path, headers=headers)
            assert res.status_code == 404, path
            assert res.json()["success"] is False, path

    def test_requires_auth(self, client_seeded):
        scan_id = _create_scan(client_seeded, _register_and_login(client_seeded, USER_A))
        for path in (
            f"/api/v1/scans/{scan_id}/findings",
            f"/api/v1/scans/{scan_id}/assets",
            f"/api/v1/scans/{scan_id}/agent-events",
            f"/api/v1/scans/{scan_id}/tool-runs",
        ):
            res = client_seeded.get(path)
            assert res.status_code == 401, path
            assert res.json()["error"]["code"] == "INVALID_CREDENTIALS", path


class TestResourceCursorPagination:
    def test_agent_events_cursor_params(self, client_seeded):
        """after_id + limit are accepted; empty result for a fresh scan."""
        headers = _register_and_login(client_seeded, USER_A)
        scan_id = _create_scan(client_seeded, headers)
        res = client_seeded.get(
            f"/api/v1/scans/{scan_id}/agent-events",
            params={"after_id": 0, "limit": 10},
            headers=headers,
        )
        assert res.status_code == 200
        body = res.json()
        assert body["data"]["items"] == []
        assert body["meta"]["page_size"] == 10

    def test_agent_events_limit_capped_at_100(self, client_seeded):
        headers = _register_and_login(client_seeded, USER_A)
        scan_id = _create_scan(client_seeded, headers)
        res = client_seeded.get(
            f"/api/v1/scans/{scan_id}/agent-events", params={"limit": 500}, headers=headers
        )
        assert res.status_code == 422

    def test_pagination_params_honored(self, client_seeded):
        headers = _register_and_login(client_seeded, USER_A)
        scan_id = _create_scan(client_seeded, headers)
        res = client_seeded.get(
            f"/api/v1/scans/{scan_id}/findings",
            params={"page": 2, "page_size": 5},
            headers=headers,
        )
        assert res.status_code == 200
        assert res.json()["meta"]["page"] == 2
        assert res.json()["meta"]["page_size"] == 5


class TestSingleResourceFetch:
    def test_unknown_finding_404(self, client_seeded):
        headers = _register_and_login(client_seeded, USER_A)
        res = client_seeded.get(
            "/api/v1/findings/11111111-2222-3333-4444-555555555555", headers=headers
        )
        assert res.status_code == 404
        assert res.json()["error"]["code"] == "FINDING_NOT_FOUND"

    def test_unknown_asset_404(self, client_seeded):
        headers = _register_and_login(client_seeded, USER_A)
        res = client_seeded.get(
            "/api/v1/assets/11111111-2222-3333-4444-555555555555", headers=headers
        )
        assert res.status_code == 404
