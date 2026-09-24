"""API tests: projects (CRUD, scope validation, ownership, pagination)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from integration.pg import requires_pg

pytestmark = [requires_pg, pytest.mark.usefixtures("clean_db")]

USER_A = {"email": "proj-a@test.example", "password": "password-a-123"}
USER_B = {"email": "proj-b@test.example", "password": "password-b-123"}

SCOPE = [{"type": "host", "value": "juice-shop"}, {"type": "cidr", "value": "127.0.0.0/31"}]


def _register_and_login(client: TestClient, user: dict) -> dict:
    client.post("/api/v1/auth/register", json=user)
    res = client.post(
        "/api/v1/auth/login", json={"email": user["email"], "password": user["password"]}
    )
    return {"Authorization": f"Bearer {res.json()['data']['access_token']}"}


def _create_project(client: TestClient, headers: dict, name: str = "Lab") -> dict:
    return client.post(
        "/api/v1/projects", json={"name": name, "description": "d", "scope": SCOPE}, headers=headers
    )


class TestProjectCreate:
    def test_create_201(self, client_seeded):
        headers = _register_and_login(client_seeded, USER_A)
        res = _create_project(client_seeded, headers)
        assert res.status_code == 201
        body = res.json()
        assert body["success"] is True
        assert body["data"]["name"] == "Lab"
        assert body["data"]["scope"][0]["value"] == "juice-shop"
        assert body["meta"]["request_id"]

    def test_requires_auth(self, client_seeded):
        res = _create_project(client_seeded, {})
        assert res.status_code == 401
        assert res.json()["error"]["code"] == "INVALID_CREDENTIALS"

    def test_scope_canonicalization(self, client_seeded):
        headers = _register_and_login(client_seeded, USER_A)
        res = client_seeded.post(
            "/api/v1/projects",
            json={
                "name": "canon",
                "scope": [
                    {"type": "host", "value": "Juice-Shop.LOCAL"},
                    {"type": "cidr", "value": "10.0.0.5/24"},
                    {"type": "url", "value": "http://web.local:8080"},
                ],
            },
            headers=headers,
        )
        assert res.status_code == 201
        scope = res.json()["data"]["scope"]
        assert scope[0]["value"] == "juice-shop.local"
        assert scope[1]["value"] == "10.0.0.0/24"

    def test_invalid_scope_422(self, client_seeded):
        headers = _register_and_login(client_seeded, USER_A)
        for bad in (
            [{"type": "host", "value": "not a host!"}],
            [{"type": "cidr", "value": "10.0.0.0/99"}],
            [{"type": "url", "value": "ftp://host"}],
            [{"type": "url", "value": "http://user:pass@host"}],
        ):
            res = client_seeded.post(
                "/api/v1/projects", json={"name": "x", "scope": bad}, headers=headers
            )
            assert res.status_code == 422, bad
            assert res.json()["error"]["code"] == "INVALID_TARGET"

    def test_empty_scope_422(self, client_seeded):
        headers = _register_and_login(client_seeded, USER_A)
        res = client_seeded.post(
            "/api/v1/projects", json={"name": "x", "scope": []}, headers=headers
        )
        assert res.status_code == 422


class TestProjectCrud:
    def test_detail_update_archive(self, client_seeded):
        headers = _register_and_login(client_seeded, USER_A)
        pid = _create_project(client_seeded, headers).json()["data"]["id"]

        res = client_seeded.get(f"/api/v1/projects/{pid}", headers=headers)
        assert res.status_code == 200

        res = client_seeded.patch(
            f"/api/v1/projects/{pid}",
            json={"name": "Renamed", "description": "new desc"},
            headers=headers,
        )
        assert res.status_code == 200
        assert res.json()["data"]["name"] == "Renamed"

        res = client_seeded.delete(f"/api/v1/projects/{pid}", headers=headers)
        assert res.status_code == 204
        # archive, not delete: still fetchable with status=archived
        res = client_seeded.get(f"/api/v1/projects/{pid}", headers=headers)
        assert res.status_code == 200
        assert res.json()["data"]["status"] == "archived"

    def test_unknown_project_404(self, client_seeded):
        headers = _register_and_login(client_seeded, USER_A)
        res = client_seeded.get(
            "/api/v1/projects/11111111-2222-3333-4444-555555555555", headers=headers
        )
        assert res.status_code == 404
        assert res.json()["error"]["code"] == "PROJECT_NOT_FOUND"


class TestProjectOwnershipAndPagination:
    def test_list_returns_only_owned(self, client_seeded):
        ha = _register_and_login(client_seeded, USER_A)
        hb = _register_and_login(client_seeded, USER_B)
        _create_project(client_seeded, ha, "A-project")
        _create_project(client_seeded, hb, "B-project")

        res = client_seeded.get("/api/v1/projects", headers=ha)
        names = [p["name"] for p in res.json()["data"]["items"]]
        assert names == ["A-project"]
        assert res.json()["meta"]["total"] == 1

    def test_pagination(self, client_seeded):
        headers = _register_and_login(client_seeded, USER_A)
        for i in range(3):
            _create_project(client_seeded, headers, f"p{i}")
        res = client_seeded.get(
            "/api/v1/projects", params={"page": 2, "page_size": 2}, headers=headers
        )
        body = res.json()
        assert body["meta"]["page"] == 2
        assert body["meta"]["page_size"] == 2
        assert body["meta"]["total"] == 3
        assert len(body["data"]["items"]) == 1

    def test_page_size_over_100_rejected(self, client_seeded):
        """Strict validation: page_size must be 1..100 (fail closed)."""
        headers = _register_and_login(client_seeded, USER_A)
        res = client_seeded.get(
            "/api/v1/projects", params={"page_size": 500}, headers=headers
        )
        assert res.status_code == 422
        assert res.json()["error"]["code"] == "VALIDATION_ERROR"

    def test_admin_sees_all(self, client_seeded):
        ha = _register_and_login(client_seeded, USER_A)
        _create_project(client_seeded, ha, "A-project")
        # admin logs in with the seeded credentials
        res = client_seeded.post(
            "/api/v1/auth/login",
            json={"email": "admin@aicybersec.dev", "password": "admin-dev-password-change-me"},
        )
        admin_headers = {"Authorization": f"Bearer {res.json()['data']['access_token']}"}
        res = client_seeded.get("/api/v1/projects", headers=admin_headers)
        names = [p["name"] for p in res.json()["data"]["items"]]
        assert "A-project" in names

    def test_admin_can_access_other_users_project(self, client_seeded):
        ha = _register_and_login(client_seeded, USER_A)
        pid = _create_project(client_seeded, ha).json()["data"]["id"]
        res = client_seeded.post(
            "/api/v1/auth/login",
            json={"email": "admin@aicybersec.dev", "password": "admin-dev-password-change-me"},
        )
        admin_headers = {"Authorization": f"Bearer {res.json()['data']['access_token']}"}
        assert client_seeded.get(f"/api/v1/projects/{pid}", headers=admin_headers).status_code == 200
