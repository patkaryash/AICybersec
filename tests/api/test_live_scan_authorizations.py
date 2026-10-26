"""API tests: live website authorizations + live_probe scans (Stage 1).

Covers (PostgreSQL-backed, like the other API suites):
- Admin-only activation (non-admin create/suspend/revoke -> 403).
- Project ownership/anti-enumeration (consistent 404) for reads.
- Evidence requirement, origin rejections, lifetime cap.
- Suspended/revoked/expired/not-yet-valid authorizations cannot be used.
- Cross-project authorization references rejected (403); invisible
  projects -> 404.
- Feature flag gate: live_probe scan creation rejected while disabled;
  snapshot copy + target_snapshot separation while enabled.
- Changing project scope never mutates the authorization snapshot.
- No execution in Stage 1 is asserted by the integration suite
  (ScanManager refusal); here only the API plane is exercised.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from backend.core.config import get_backend_settings
from integration.pg import requires_pg

pytestmark = [requires_pg, pytest.mark.usefixtures("clean_db")]

USER_A = {"email": "live-a@test.example", "password": "password-a-123"}
USER_B = {"email": "live-b@test.example", "password": "password-b-123"}
UNKNOWN_ID = "11111111-2222-3333-4444-555555555555"


def _login(client: TestClient, user: dict) -> dict:
    res = client.post(
        "/api/v1/auth/login", json={"email": user["email"], "password": user["password"]}
    )
    return {"Authorization": f"Bearer {res.json()['data']['access_token']}"}


def _register_and_login(client: TestClient, user: dict) -> dict:
    client.post("/api/v1/auth/register", json=user)
    return _login(client, user)


def _admin(client: TestClient) -> dict:
    return _login(
        client,
        {"email": "admin@aicybersec.dev", "password": "admin-dev-password-change-me"},
    )


def _project(client: TestClient, headers: dict, name: str = "Lab") -> str:
    res = client.post(
        "/api/v1/projects",
        json={
            "name": name,
            "scope": [
                {"type": "url", "value": "https://example.com"},
            ],
        },
        headers=headers,
    )
    assert res.status_code == 201
    return res.json()["data"]["id"]


def _auth(
    client: TestClient,
    headers: dict,
    project_id: str,
    *,
    origins=("https://example.com",),
    exclusions=(),
    evidence_ref="signed-authorization.pdf",
    evidence_sha256=None,
    valid_from=None,
    valid_until=None,
) -> dict:
    payload = {
        "project_id": project_id,
        "origins": list(origins),
        "exclusions": list(exclusions),
    }
    if evidence_ref:
        payload["evidence_ref"] = evidence_ref
    if evidence_sha256:
        payload["evidence_sha256"] = evidence_sha256
    if valid_from:
        payload["valid_from"] = valid_from
    if valid_until:
        payload["valid_until"] = valid_until
    res = client.post("/api/v1/live-authorizations", json=payload, headers=headers)
    assert res.status_code == 201, res.text
    return res.json()["data"]


def _scan(client: TestClient, headers: dict, project_id: str, auth_id: str) -> object:
    return client.post(
        "/api/v1/scans",
        json={
            "project_id": project_id,
            "profile": "live_probe",
            "live_authorization_id": auth_id,
        },
        headers=headers,
    )


def _enable_live_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    """Enable the live flag for one test WITHOUT touching DB engine
    caches (only the settings cache; monkeypatch restores the env var
    to its previous state afterwards)."""
    monkeypatch.setenv("AICYBERSEC_LIVE_PROBE_ENABLED", "1")
    from backend.core.config import get_backend_settings

    get_backend_settings.cache_clear()


@pytest.fixture(autouse=True)
def _refresh_settings_cache_after_test():
    """Rebuild the settings cache AFTER env restoration so no test ever
    leaks live_probe_enabled=True into a later test."""
    yield
    from backend.core.config import get_backend_settings

    get_backend_settings.cache_clear()


class TestAuthorizationCreation:
    def test_non_admin_creation_rejected_403(self, client_seeded):
        headers = _register_and_login(client_seeded, USER_A)
        pid = _project(client_seeded, headers)
        res = client_seeded.post(
            "/api/v1/live-authorizations",
            json={"project_id": pid, "origins": ["https://example.com"], "evidence_ref": "x"},
            headers=headers,
        )
        assert res.status_code == 403
        assert res.json()["error"]["code"] == "ADMIN_REQUIRED"

    def test_non_admin_suspend_revoke_rejected_403(self, client_seeded):
        admin = _admin(client_seeded)
        headers_a = _register_and_login(client_seeded, USER_A)
        pid = _project(client_seeded, headers_a)
        auth = _auth(client_seeded, admin, pid)
        for action in ("suspend", "revoke"):
            res = client_seeded.post(
                f"/api/v1/live-authorizations/{auth['id']}/{action}", headers=headers_a
            )
            assert res.status_code == 403

    def test_admin_creation_201(self, client_seeded):
        admin = _admin(client_seeded)
        headers_a = _register_and_login(client_seeded, USER_A)
        pid = _project(client_seeded, headers_a)
        res = client_seeded.post(
            "/api/v1/live-authorizations",
            json={
                "project_id": pid,
                "origins": ["https://Example.COM", "http://other.example.com:80"],
                "evidence_ref": "signed-agreement-4301",
            },
            headers=admin,
        )
        assert res.status_code == 201, res.text
        data = res.json()["data"]
        assert data["status"] == "active"
        assert data["policy_version"] == "live-probe/v1"
        # canonicalized origins; 80 -> http default
        assert {(o["origin"], o["port"]) for o in data["origins"]} == {
            ("https://example.com", 443),
            ("http://other.example.com", 80),
        }
        assert data["methods"] == ["GET"]
        assert data["valid_until"] > data["valid_from"]
        assert data["approved_at"] is not None

    def test_missing_evidence_rejected_422(self, client_seeded):
        admin = _admin(client_seeded)
        headers_a = _register_and_login(client_seeded, USER_A)
        pid = _project(client_seeded, headers_a)
        res = client_seeded.post(
            "/api/v1/live-authorizations",
            json={"project_id": pid, "origins": ["https://example.com"]},
            headers=admin,
        )
        assert res.status_code == 422
        assert res.json()["error"]["code"] == "LIVE_AUTHORIZATION_INVALID"

    def test_evidence_hash_only_accepted_ref_only_accepted(self, client_seeded):
        admin = _admin(client_seeded)
        headers_a = _register_and_login(client_seeded, USER_A)
        pid = _project(client_seeded, headers_a)
        sha = "ab" * 32
        res = client_seeded.post(
            "/api/v1/live-authorizations",
            json={
                "project_id": pid,
                "origins": ["https://example.com"],
                "evidence_sha256": sha.upper(),  # normalized to lowercase
            },
            headers=admin,
        )
        assert res.status_code == 201
        assert res.json()["data"]["evidence_sha256"] == sha

    @pytest.mark.parametrize(
        "raw",
        [
            "https://*.example.com",
            "ftp://example.com",
            "example.com",
            "http://user:pw@example.com",
            "https://example.com/path",
            "https://example.com/",
            "https://example.com/?q=1",
            "https://example.com/#frag",
            # F1: IP literals (incl. metadata + IPv6 spellings) rejected
            "http://127.0.0.1",
            "http://169.254.169.254",
            "http://[::1]:80",
            "http://::1",
            "https://[2001:db8::1]:443",
            "http://::ffff:127.0.0.1",
            "https://12345",
            # F4: raw empty-delimiter spellings rejected
            "https://example.com?",
            "https://example.com#",
            "https://example.com/#",
            "http://example.com:8080",
            "https://example.com:80",
        ],
    )
    def test_invalid_live_origin_rejected_422(self, client_seeded, raw):
        admin = _admin(client_seeded)
        headers_a = _register_and_login(client_seeded, USER_A)
        pid = _project(client_seeded, headers_a)
        res = client_seeded.post(
            "/api/v1/live-authorizations",
            json={
                "project_id": pid,
                "origins": [raw],
                "evidence_ref": "evidence",
            },
            headers=admin,
        )
        assert res.status_code == 422, raw
        assert res.json()["error"]["code"] == "LIVE_AUTHORIZATION_INVALID"

    def test_lifetime_cap_enforced(self, client_seeded):
        admin = _admin(client_seeded)
        headers_a = _register_and_login(client_seeded, USER_A)
        pid = _project(client_seeded, headers_a)
        now = datetime.now(timezone.utc)
        res = client_seeded.post(
            "/api/v1/live-authorizations",
            json={
                "project_id": pid,
                "origins": ["https://example.com"],
                "evidence_ref": "evidence",
                "valid_from": now.isoformat(),
                "valid_until": (now + timedelta(days=91, minutes=1)).isoformat(),
            },
            headers=admin,
        )
        assert res.status_code == 422
        # exactly 90 days is fine
        ok = client_seeded.post(
            "/api/v1/live-authorizations",
            json={
                "project_id": pid,
                "origins": ["https://example.com"],
                "evidence_ref": "evidence",
                "valid_from": now.isoformat(),
                "valid_until": (now + timedelta(days=90)).isoformat(),
            },
            headers=admin,
        )
        assert ok.status_code == 201

    def test_default_window_is_max_days(self, client_seeded):
        admin = _admin(client_seeded)
        headers_a = _register_and_login(client_seeded, USER_A)
        pid = _project(client_seeded, headers_a)
        auth = _auth(client_seeded, admin, pid)
        vf = datetime.fromisoformat(auth["valid_from"])
        vu = datetime.fromisoformat(auth["valid_until"])
        assert timedelta(days=89) < vu - vf <= timedelta(days=90, seconds=5)

    def test_exclusions_may_not_remove_every_origin(self, client_seeded):
        admin = _admin(client_seeded)
        headers_a = _register_and_login(client_seeded, USER_A)
        pid = _project(client_seeded, headers_a)
        res = client_seeded.post(
            "/api/v1/live-authorizations",
            json={
                "project_id": pid,
                "origins": ["https://example.com"],
                "exclusions": ["https://example.com"],
                "evidence_ref": "evidence",
            },
            headers=admin,
        )
        assert res.status_code == 422


class TestAuthorizationReadsAndIdor:
    def test_owner_sees_own_authorization(self, client_seeded):
        admin = _admin(client_seeded)
        headers_a = _register_and_login(client_seeded, USER_A)
        pid = _project(client_seeded, headers_a)
        auth = _auth(client_seeded, admin, pid)
        res = client_seeded.get(f"/api/v1/live-authorizations/{auth['id']}", headers=headers_a)
        assert res.status_code == 200

    def test_owner_response_hides_evidence_and_approver_f6(self, client_seeded):
        admin = _admin(client_seeded)
        headers_a = _register_and_login(client_seeded, USER_A)
        pid = _project(client_seeded, headers_a)
        auth = _auth(client_seeded, admin, pid)
        res = client_seeded.get(f"/api/v1/live-authorizations/{auth['id']}", headers=headers_a)
        assert res.status_code == 200
        data = res.json()["data"]
        # F6: owner does NOT receive evidence/approver audit metadata
        assert "evidence_ref" not in data
        assert "evidence_sha256" not in data
        assert "approved_by" not in data
        # lifecycle mechanics remain visible to the owner
        for key in (
            "id", "project_id", "status", "policy_version", "origins",
            "exclusions", "methods", "valid_from", "valid_until",
        ):
            assert key in data, key
        assert data["status"] == "active"

    def test_owner_list_hides_evidence_and_approver_f6(self, client_seeded):
        admin = _admin(client_seeded)
        headers_a = _register_and_login(client_seeded, USER_A)
        pid = _project(client_seeded, headers_a)
        _auth(client_seeded, admin, pid)
        items = client_seeded.get("/api/v1/live-authorizations", headers=headers_a).json()[
            "data"
        ]["items"]
        assert len(items) == 1
        for key in ("evidence_ref", "evidence_sha256", "approved_by"):
            assert key not in items[0], key

    def test_admin_full_audit_view_preserved_f6(self, client_seeded):
        admin = _admin(client_seeded)
        headers_a = _register_and_login(client_seeded, USER_A)
        pid = _project(client_seeded, headers_a)
        auth = _auth(
            client_seeded, admin, pid, evidence_ref="doc-4301", evidence_sha256="ab" * 32
        )
        res = client_seeded.get(f"/api/v1/live-authorizations/{auth['id']}", headers=admin)
        assert res.status_code == 200
        data = res.json()["data"]
        assert data["evidence_ref"] == "doc-4301"
        assert data["evidence_sha256"] == "ab" * 32
        assert data["approved_by"] is not None

    def test_creation_and_lifecycle_use_full_admin_view(self, client_seeded):
        """Activation + lifecycle endpoints are admin-only -> full DTO."""
        admin = _admin(client_seeded)
        headers_a = _register_and_login(client_seeded, USER_A)
        pid = _project(client_seeded, headers_a)
        auth = _auth(client_seeded, admin, pid)
        assert auth["approved_by"]
        res = client_seeded.post(
            f"/api/v1/live-authorizations/{auth['id']}/suspend", headers=admin
        )
        assert res.json()["data"]["evidence_ref"] == "signed-authorization.pdf"

    def test_other_user_gets_consistent_404(self, client_seeded):
        admin = _admin(client_seeded)
        headers_a = _register_and_login(client_seeded, USER_A)
        headers_b = _register_and_login(client_seeded, USER_B)
        pid = _project(client_seeded, headers_a)
        auth = _auth(client_seeded, admin, pid)
        res = client_seeded.get(f"/api/v1/live-authorizations/{auth['id']}", headers=headers_b)
        assert res.status_code == 404
        assert res.json()["error"]["code"] == "LIVE_AUTHORIZATION_NOT_FOUND"

    def test_list_is_owner_scoped(self, client_seeded):
        admin = _admin(client_seeded)
        headers_a = _register_and_login(client_seeded, USER_A)
        headers_b = _register_and_login(client_seeded, USER_B)
        pid_a = _project(client_seeded, headers_a)
        pid_b = _project(client_seeded, headers_b)
        _auth(client_seeded, admin, pid_a)
        _auth(client_seeded, admin, pid_b)

        items = client_seeded.get("/api/v1/live-authorizations", headers=headers_a).json()[
            "data"
        ]["items"]
        assert len(items) == 1
        assert client_seeded.get(
            "/api/v1/live-authorizations", params={"project_id": pid_b}, headers=headers_a
        ).status_code == 404
        admin_items = client_seeded.get(
            "/api/v1/live-authorizations", headers=admin
        ).json()["data"]["items"]
        assert len(admin_items) == 2


class TestAuthorizationLifecycle:
    def test_suspend_then_revoke(self, client_seeded):
        admin = _admin(client_seeded)
        headers_a = _register_and_login(client_seeded, USER_A)
        pid = _project(client_seeded, headers_a)
        aid = _auth(client_seeded, admin, pid)["id"]
        res = client_seeded.post(f"/api/v1/live-authorizations/{aid}/suspend", headers=admin)
        assert res.status_code == 200
        assert res.json()["data"]["status"] == "suspended"
        # not resumable in v1: no resume endpoint
        res = client_seeded.get("/api/v1/openapi.json")
        paths = res.json()["paths"]
        assert not any("/resume" in p for p in paths)

    def test_double_suspend_409(self, client_seeded):
        admin = _admin(client_seeded)
        headers_a = _register_and_login(client_seeded, USER_A)
        pid = _project(client_seeded, headers_a)
        aid = _auth(client_seeded, admin, pid)["id"]
        client_seeded.post(f"/api/v1/live-authorizations/{aid}/suspend", headers=admin)
        res = client_seeded.post(f"/api/v1/live-authorizations/{aid}/suspend", headers=admin)
        assert res.status_code == 409
        assert res.json()["error"]["code"] == "LIVE_AUTHORIZATION_INVALID_STATE"

    def test_double_revoke_409(self, client_seeded):
        admin = _admin(client_seeded)
        headers_a = _register_and_login(client_seeded, USER_A)
        pid = _project(client_seeded, headers_a)
        aid = _auth(client_seeded, admin, pid)["id"]
        client_seeded.post(f"/api/v1/live-authorizations/{aid}/revoke", headers=admin)
        res = client_seeded.post(f"/api/v1/live-authorizations/{aid}/revoke", headers=admin)
        assert res.status_code == 409


class TestLiveScanGates:
    def test_feature_flag_disabled_rejects_403(self, client_seeded):
        # default config: AICYBERSEC_LIVE_PROBE_ENABLED=false
        admin = _admin(client_seeded)
        headers_a = _register_and_login(client_seeded, USER_A)
        pid = _project(client_seeded, headers_a)
        auth = _auth(client_seeded, admin, pid)
        s = get_backend_settings()
        assert s.live_probe_enabled is False
        res = _scan(client_seeded, headers_a, pid, auth["id"])
        assert res.status_code == 403
        assert res.json()["error"]["code"] == "LIVE_SCAN_NOT_PERMITTED"

    def test_missing_authorization_id_rejected_422(self, client_seeded, monkeypatch):
        _enable_live_flag(monkeypatch)
        headers_a = _register_and_login(client_seeded, USER_A)
        pid = _project(client_seeded, headers_a)
        res = client_seeded.post(
            "/api/v1/scans",
            json={"project_id": pid, "profile": "live_probe"},
            headers=headers_a,
        )
        assert res.status_code == 422
        assert res.json()["error"]["code"] == "LIVE_AUTHORIZATION_INVALID"

    def test_cross_project_authorization_rejected_403(self, client_seeded, monkeypatch):
        _enable_live_flag(monkeypatch)
        admin = _admin(client_seeded)
        headers_a = _register_and_login(client_seeded, USER_A)
        pid_a = _project(client_seeded, headers_a, "A")
        pid_a2 = _project(client_seeded, headers_a, "A2")
        # authorization belongs to another of A's projects
        auth = _auth(client_seeded, admin, pid_a2)
        res = _scan(client_seeded, headers_a, pid_a, auth["id"])
        assert res.status_code == 403
        assert res.json()["error"]["code"] == "LIVE_SCAN_NOT_PERMITTED"

    def test_invisible_authorization_is_404_not_403(self, client_seeded, monkeypatch):
        _enable_live_flag(monkeypatch)
        admin = _admin(client_seeded)
        headers_a = _register_and_login(client_seeded, USER_A)
        headers_b = _register_and_login(client_seeded, USER_B)
        pid_b = _project(client_seeded, headers_b, "B")
        pid_a = _project(client_seeded, headers_a, "A")
        # B's authorization referenced by A -> consistent 404 (anti-enumeration)
        auth_b = _auth(client_seeded, admin, pid_b)
        res = _scan(client_seeded, headers_a, pid_a, auth_b["id"])
        assert res.status_code == 404
        assert res.json()["error"]["code"] == "LIVE_AUTHORIZATION_NOT_FOUND"

    def test_happy_path_creates_immutable_snapshot(self, client_seeded, monkeypatch):
        _enable_live_flag(monkeypatch)
        admin = _admin(client_seeded)
        headers_a = _register_and_login(client_seeded, USER_A)
        pid = _project(client_seeded, headers_a)
        auth = _auth(client_seeded, admin, pid)
        res = _scan(client_seeded, headers_a, pid, auth["id"])
        assert res.status_code == 202, res.text
        data = res.json()["data"]
        assert data["status"] == "queued"
        assert data["profile"] == "live_probe"
        # key separation invariant: live scans are anchored by the
        # snapshot, NOT by project scope / target_snapshot
        assert data["target_snapshot"] == []
        snap = data["authorization_snapshot"]
        assert snap["authorization_id"] == auth["id"]
        assert snap["project_id"] == pid
        assert snap["policy_version"] == "live-probe/v1"
        assert snap["follow_redirects"] is False
        assert snap["discovery"] is False
        assert snap["methods"] == ["GET"]
        assert snap["paths"] == ["/"]
        # digest is computed over the payload minus the digest itself
        import hashlib
        import json as jsonlib

        core = {k: v for k, v in snap.items() if k != "digest"}
        canonical = jsonlib.dumps(
            core, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        assert (
            hashlib.sha256(canonical.encode()).hexdigest() == snap["digest"]
            == data["authorization_snapshot_digest"]
        )

    def test_scope_change_does_not_mutate_snapshot(self, client_seeded, monkeypatch):
        _enable_live_flag(monkeypatch)
        admin = _admin(client_seeded)
        headers_a = _register_and_login(client_seeded, USER_A)
        pid = _project(client_seeded, headers_a)
        auth = _auth(client_seeded, admin, pid)
        scan_id = _scan(client_seeded, headers_a, pid, auth["id"]).json()["data"]["id"]
        before = client_seeded.get(
            f"/api/v1/scans/{scan_id}", headers=headers_a
        ).json()["data"]
        # point the project at a completely different target AFTER creation
        client_seeded.patch(
            f"/api/v1/projects/{pid}",
            json={"scope": [{"type": "url", "value": "https://other-host.test"}]},
            headers=headers_a,
        )
        after = client_seeded.get(
            f"/api/v1/scans/{scan_id}", headers=headers_a
        ).json()["data"]
        assert after["authorization_snapshot"] == before["authorization_snapshot"]
        assert after["authorization_snapshot_digest"] == before["authorization_snapshot_digest"]
        assert after["target_snapshot"] == []

    def test_suspended_authorization_cannot_be_used(self, client_seeded, monkeypatch):
        _enable_live_flag(monkeypatch)
        admin = _admin(client_seeded)
        headers_a = _register_and_login(client_seeded, USER_A)
        pid = _project(client_seeded, headers_a)
        auth = _auth(client_seeded, admin, pid)
        aid = auth["id"]
        client_seeded.post(f"/api/v1/live-authorizations/{aid}/suspend", headers=admin)
        res = _scan(client_seeded, headers_a, pid, aid)
        assert res.status_code == 403
        assert "suspended" in res.json()["error"]["message"]

    def test_revoked_authorization_cannot_be_used(self, client_seeded, monkeypatch):
        _enable_live_flag(monkeypatch)
        admin = _admin(client_seeded)
        headers_a = _register_and_login(client_seeded, USER_A)
        pid = _project(client_seeded, headers_a)
        aid = _auth(client_seeded, admin, pid)["id"]
        client_seeded.post(f"/api/v1/live-authorizations/{aid}/revoke", headers=admin)
        res = _scan(client_seeded, headers_a, pid, aid)
        assert res.status_code == 403
        assert "revoked" in res.json()["error"]["message"]

    def test_not_yet_valid_authorization_cannot_be_used(self, client_seeded, monkeypatch):
        _enable_live_flag(monkeypatch)
        admin = _admin(client_seeded)
        headers_a = _register_and_login(client_seeded, USER_A)
        pid = _project(client_seeded, headers_a)
        now = datetime.now(timezone.utc)
        auth = _auth(
            client_seeded,
            admin,
            pid,
            valid_from=(now + timedelta(days=1)).isoformat(),
            valid_until=(now + timedelta(days=30)).isoformat(),
        )
        res = _scan(client_seeded, headers_a, pid, auth["id"])
        assert res.status_code == 403
        assert "not yet valid" in res.json()["error"]["message"]

    def test_expired_authorization_cannot_be_used(self, client_seeded, monkeypatch):
        _enable_live_flag(monkeypatch)
        admin = _admin(client_seeded)
        headers_a = _register_and_login(client_seeded, USER_A)
        pid = _project(client_seeded, headers_a)
        now = datetime.now(timezone.utc)
        auth = _auth(
            client_seeded,
            admin,
            pid,
            valid_from=(now - timedelta(days=10)).isoformat(),
            valid_until=(now - timedelta(days=1)).isoformat(),
        )
        res = _scan(client_seeded, headers_a, pid, auth["id"])
        assert res.status_code == 403
        assert "expired" in res.json()["error"]["message"]

    def test_exclusions_narrow_effective_origins(self, client_seeded, monkeypatch):
        _enable_live_flag(monkeypatch)
        admin = _admin(client_seeded)
        headers_a = _register_and_login(client_seeded, USER_A)
        pid = _project(client_seeded, headers_a)
        auth = _auth(
            client_seeded,
            admin,
            pid,
            origins=("https://example.com", "https://keep.example.net"),
            exclusions=("https://example.com",),
        )
        res = _scan(client_seeded, headers_a, pid, auth["id"])
        assert res.status_code == 202
        snap = res.json()["data"]["authorization_snapshot"]
        origins = [o["origin"] for o in snap["origins"]]
        exclusions = [o["origin"] for o in snap["exclusions"]]
        assert origins == ["https://example.com", "https://keep.example.net"]
        assert exclusions == ["https://example.com"]
        # exclusions take precedence: the effective set keeps only 'keep'
        from backend.services.live_authorization_service import effective_origins

        assert [o["origin"] for o in effective_origins(snap["origins"], snap["exclusions"])] == [
            "https://keep.example.net"
        ]

    def test_existing_profiles_unaffected(self, client_seeded):
        headers_a = _register_and_login(client_seeded, USER_A)
        pid = _project(client_seeded, headers_a)
        for profile in ("recon", "web", "full"):
            res = client_seeded.post(
                "/api/v1/scans",
                json={"project_id": pid, "profile": profile},
                headers=headers_a,
            )
            # second active scan rejected 409 regardless of profile
            if profile == "recon":
                assert res.status_code == 202
            else:
                assert res.status_code == 409
        res = client_seeded.post(
            "/api/v1/scans",
            json={"project_id": pid, "profile": "nonsense"},
            headers=headers_a,
        )
        assert res.status_code == 422

class TestLiveScanBudgetPinning:
    """F3: live scans ignore ALL client-supplied execution parameters
    and carry the pinned server-side budgets (validated at creation; the
    scan still never executes in Stage 1 - see TestLiveProbeExecutionGate
    integration coverage for the manager-level refusal)."""

    def test_client_execution_params_discarded(self, client_seeded, monkeypatch):
        _enable_live_flag(monkeypatch)
        from backend.services import live_probe_budgets as budgets

        admin = _admin(client_seeded)
        headers_a = _register_and_login(client_seeded, USER_A)
        pid = _project(client_seeded, headers_a)
        auth = _auth(client_seeded, admin, pid)
        res = client_seeded.post(
            "/api/v1/scans",
            json={
                "project_id": pid,
                "profile": "live_probe",
                "live_authorization_id": auth["id"],
                "mode": "agent",
                "max_steps": 100,
                "tool_timeout_s": 1800,
            },
            headers=headers_a,
        )
        assert res.status_code == 202, res.text
        data = res.json()["data"]
        assert data["mode"] == budgets.LIVE_PROBE_PINNED_MODE
        assert data["tool_timeout_s"] == budgets.LIVE_PROBE_PINNED_TOOL_TIMEOUT_S
        scan_id = data["id"]
        after = client_seeded.get(
            f"/api/v1/scans/{scan_id}", headers=headers_a
        ).json()["data"]
        assert after["tool_timeout_s"] == budgets.LIVE_PROBE_PINNED_TOOL_TIMEOUT_S
        assert after["mode"] == budgets.LIVE_PROBE_PINNED_MODE

    def test_pinned_constants_are_stage1_contract(self):
        from backend.services import live_probe_budgets as budgets

        assert budgets.LIVE_PROBE_PINNED_MODE == "pipeline"
        assert budgets.LIVE_PROBE_PINNED_MAX_STEPS == 1
        assert 0 < budgets.LIVE_PROBE_PINNED_TOOL_TIMEOUT_S < 600
        # Stage 2 transport budgets exist and are sane/strict
        assert budgets.LIVE_PROBE_SCAN_REQUEST_BUDGET > 0
        assert budgets.LIVE_PROBE_REQUESTS_PER_SECOND >= 1
        assert budgets.LIVE_PROBE_REQUEST_TIMEOUT_S < budgets.LIVE_PROBE_PINNED_TOOL_TIMEOUT_S
        assert budgets.LIVE_PROBE_SCAN_WALL_CLOCK_S > budgets.LIVE_PROBE_REQUEST_TIMEOUT_S
        assert budgets.LIVE_PROBE_RESPONSE_MAX_BYTES <= 262_144
        assert budgets.LIVE_PROBE_MAX_CONCURRENT_CONNECTIONS <= 2
