"""API tests: IDOR matrix - User A vs User B resource isolation.

User A -> Project A -> Scan A; User B -> Project B -> Scan B.
A must NOT be able to access any of B's resources (404, consistent,
no enumeration). Legitimate access keeps working; admin sees all.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from integration.pg import requires_pg

pytestmark = [requires_pg, pytest.mark.usefixtures("clean_db")]

USER_A = {"email": "idor-a@test.example", "password": "password-a-123"}
USER_B = {"email": "idor-b@test.example", "password": "password-b-123"}
NOT_OWNED_ID = "11111111-2222-3333-4444-555555555555"


def _register_and_login(client: TestClient, user: dict) -> dict:
    client.post("/api/v1/auth/register", json=user)
    res = client.post(
        "/api/v1/auth/login", json={"email": user["email"], "password": user["password"]}
    )
    return {"Authorization": f"Bearer {res.json()['data']['access_token']}"}


def _admin_headers(client: TestClient) -> dict:
    res = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@aicybersec.dev", "password": "admin-dev-password-change-me"},
    )
    return {"Authorization": f"Bearer {res.json()['data']['access_token']}"}


@pytest.fixture()
def world(client_seeded):
    """User A + Project A + Scan A; User B + Project B + Scan B."""
    ha = _register_and_login(client_seeded, USER_A)
    hb = _register_and_login(client_seeded, USER_B)

    def make(headers: dict, name: str) -> tuple[str, str]:
        pid = client_seeded.post(
            "/api/v1/projects",
            json={"name": name, "scope": [{"type": "host", "value": "juice-shop"}]},
            headers=headers,
        ).json()["data"]["id"]
        scan_id = client_seeded.post(
            "/api/v1/scans", json={"project_id": pid, "profile": "full"}, headers=headers
        ).json()["data"]["id"]
        return pid, scan_id

    pid_a, scan_a = make(ha, "Project A")
    pid_b, scan_b = make(hb, "Project B")
    return {
        "ha": ha,
        "hb": hb,
        "admin": _admin_headers(client_seeded),
        "pid_a": pid_a,
        "pid_b": pid_b,
        "scan_a": scan_a,
        "scan_b": scan_b,
    }


class TestIdorMatrix:
    def test_user_a_cannot_access_user_b_resources(self, client_seeded, world):
        ha, pid_b, scan_b = world["ha"], world["pid_b"], world["scan_b"]
        # Project B
        assert client_seeded.get(f"/api/v1/projects/{pid_b}", headers=ha).status_code == 404
        # Scan B
        assert client_seeded.get(f"/api/v1/scans/{scan_b}", headers=ha).status_code == 404
        # Scan B's nested resources
        for path in (
            f"/api/v1/scans/{scan_b}/findings",
            f"/api/v1/scans/{scan_b}/assets",
            f"/api/v1/scans/{scan_b}/agent-events",
            f"/api/v1/scans/{scan_b}/tool-runs",
        ):
            res = client_seeded.get(path, headers=ha)
            assert res.status_code == 404, path
            assert res.json()["success"] is False, path
        # Scan B cancel
        assert (
            client_seeded.post(f"/api/v1/scans/{scan_b}/cancel", headers=ha).status_code
            == 404
        )
        # Scan list filtered by B's project id
        res = client_seeded.get(
            "/api/v1/scans", params={"project_id": pid_b}, headers=ha
        )
        assert res.status_code == 404

    def test_user_b_cannot_access_user_a_resources(self, client_seeded, world):
        hb, pid_a, scan_a = world["hb"], world["pid_a"], world["scan_a"]
        assert client_seeded.get(f"/api/v1/projects/{pid_a}", headers=hb).status_code == 404
        assert client_seeded.get(f"/api/v1/scans/{scan_a}", headers=hb).status_code == 404
        for path in (
            f"/api/v1/scans/{scan_a}/findings",
            f"/api/v1/scans/{scan_a}/assets",
            f"/api/v1/scans/{scan_a}/agent-events",
            f"/api/v1/scans/{scan_a}/tool-runs",
        ):
            assert client_seeded.get(path, headers=hb).status_code == 404, path

    def test_404_is_consistent_for_missing_and_unauthorized(self, client_seeded, world):
        """Unknown and unauthorized resources return identical 404s
        (no resource-existence disclosure)."""
        ha = world["ha"]
        unknown = client_seeded.get(f"/api/v1/projects/{NOT_OWNED_ID}", headers=ha)
        unauthorized = client_seeded.get(f"/api/v1/projects/{world['pid_b']}", headers=ha)
        assert unknown.status_code == unauthorized.status_code == 404
        assert unknown.json()["error"]["code"] == unauthorized.json()["error"]["code"]
        assert unknown.json()["error"]["message"] == unauthorized.json()["error"]["message"]

    def test_legitimate_access_works(self, client_seeded, world):
        ha, hb = world["ha"], world["hb"]
        # A can access A
        assert client_seeded.get(f"/api/v1/projects/{world['pid_a']}", headers=ha).status_code == 200
        assert client_seeded.get(f"/api/v1/scans/{world['scan_a']}", headers=ha).status_code == 200
        for path in (
            f"/api/v1/scans/{world['scan_a']}/findings",
            f"/api/v1/scans/{world['scan_a']}/assets",
            f"/api/v1/scans/{world['scan_a']}/agent-events",
            f"/api/v1/scans/{world['scan_a']}/tool-runs",
        ):
            assert client_seeded.get(path, headers=ha).status_code == 200, path
        # B can access B
        assert client_seeded.get(f"/api/v1/projects/{world['pid_b']}", headers=hb).status_code == 200
        assert client_seeded.get(f"/api/v1/scans/{world['scan_b']}", headers=hb).status_code == 200

    def test_admin_can_access_both(self, client_seeded, world):
        admin = world["admin"]
        for pid in (world["pid_a"], world["pid_b"]):
            assert client_seeded.get(f"/api/v1/projects/{pid}", headers=admin).status_code == 200
        for scan_id in (world["scan_a"], world["scan_b"]):
            assert client_seeded.get(f"/api/v1/scans/{scan_id}", headers=admin).status_code == 200
