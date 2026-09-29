"""API tests: Phase 4A foundation (requires isolated scratch PostgreSQL).

Proves the new scope/asset surface end to end WITHOUT touching the
demo/dev database: the suite runs only when AICYBERSEC_DATABASE_URL
points at a reachable server (see integration/pg.py), and the
clean_db fixture truncates that database only. Run migrations against
the scratch DB first (alembic upgrade head).
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from integration.pg import requires_pg

pytestmark = [requires_pg, pytest.mark.usefixtures("clean_db")]

USER_A = {"email": "p4a-a@test.example", "password": "password-a-123"}


def _auth_headers(client: TestClient) -> dict:
    client.post("/api/v1/auth/register", json=USER_A)
    res = client.post(
        "/api/v1/auth/login",
        json={"email": USER_A["email"], "password": USER_A["password"]},
    )
    assert res.status_code == 200
    return {"Authorization": f"Bearer {res.json()['data']['access_token']}"}


class TestDomainScopeApi:
    def test_create_project_with_domain_scope(self, client_seeded):
        headers = _auth_headers(client_seeded)
        res = client_seeded.post(
            "/api/v1/projects",
            json={
                "name": "Domain Lab",
                "scope": [{"type": "domain", "value": "Example.COM"}],
            },
            headers=headers,
        )
        assert res.status_code == 201
        body = res.json()["data"]
        assert body["scope"] == [{"type": "domain", "value": "example.com", "note": None}]

    def test_create_project_with_mixed_scope(self, client_seeded):
        headers = _auth_headers(client_seeded)
        res = client_seeded.post(
            "/api/v1/projects",
            json={
                "name": "Mixed Lab",
                "scope": [
                    {"type": "host", "value": "juice-shop"},
                    {"type": "cidr", "value": "10.0.0.0/24"},
                    {"type": "url", "value": "http://web.local:8080"},
                    {"type": "domain", "value": "example.com"},
                ],
            },
            headers=headers,
        )
        assert res.status_code == 201
        assert [e["type"] for e in res.json()["data"]["scope"]] == [
            "host",
            "cidr",
            "url",
            "domain",
        ]

    def test_create_project_with_wildcard_domain_rejected(self, client_seeded):
        headers = _auth_headers(client_seeded)
        res = client_seeded.post(
            "/api/v1/projects",
            json={
                "name": "Wildcard Lab",
                "scope": [{"type": "domain", "value": "*.example.com"}],
            },
            headers=headers,
        )
        assert res.status_code == 422
        assert res.json()["success"] is False

    def test_scan_snapshot_preserves_domain_entry(self, client_seeded):
        headers = _auth_headers(client_seeded)
        pid = client_seeded.post(
            "/api/v1/projects",
            json={"name": "Snap Lab", "scope": [{"type": "domain", "value": "example.com"}]},
            headers=headers,
        ).json()["data"]["id"]
        res = client_seeded.post(
            "/api/v1/scans", json={"project_id": pid, "profile": "full"}, headers=headers
        )
        assert res.status_code == 202
        snapshot = res.json()["data"]["target_snapshot"]
        assert snapshot == [{"type": "domain", "value": "example.com", "note": None}]


class TestNewAssetTypesApi:
    def _scan_id(self, client_seeded, headers: dict) -> str:
        pid = client_seeded.post(
            "/api/v1/projects",
            json={"name": "Asset Lab", "scope": [{"type": "host", "value": "juice-shop"}]},
            headers=headers,
        ).json()["data"]["id"]
        res = client_seeded.post(
            "/api/v1/scans", json={"project_id": pid, "profile": "full"}, headers=headers
        )
        assert res.status_code == 202
        return res.json()["data"]["id"]

    @pytest.mark.parametrize("asset_type", ["subdomain", "endpoint", "domain"])
    def test_asset_filter_accepts_new_types(self, client_seeded, asset_type: str):
        headers = _auth_headers(client_seeded)
        scan_id = self._scan_id(client_seeded, headers)
        res = client_seeded.get(
            f"/api/v1/scans/{scan_id}/assets",
            params={"asset_type": asset_type},
            headers=headers,
        )
        assert res.status_code == 200
        assert res.json()["data"]["items"] == []

    def test_legacy_asset_filter_still_works(self, client_seeded):
        headers = _auth_headers(client_seeded)
        scan_id = self._scan_id(client_seeded, headers)
        for asset_type in ("host", "service", "url"):
            res = client_seeded.get(
                f"/api/v1/scans/{scan_id}/assets",
                params={"asset_type": asset_type},
                headers=headers,
            )
            assert res.status_code == 200

    def test_findings_payload_carries_asset_id_field(self, client_seeded):
        headers = _auth_headers(client_seeded)
        scan_id = self._scan_id(client_seeded, headers)
        res = client_seeded.get(f"/api/v1/scans/{scan_id}/findings", headers=headers)
        assert res.status_code == 200
        assert res.json()["data"]["items"] == []
