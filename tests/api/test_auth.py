"""API tests: authentication (register, login, me) - JWT Bearer flow.

DB-backed (the client_seeded fixture hits PostgreSQL); skips cleanly
when no database is reachable.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from integration.pg import requires_pg

pytestmark = [requires_pg, pytest.mark.usefixtures("clean_db")]

from backend.core.config import get_backend_settings

USER_A = {"email": "user-a@test.example", "password": "password-a-123", "display_name": "User A"}


def _register(client: TestClient, payload: dict) -> dict:
    return client.post("/api/v1/auth/register", json=payload)


def _login(client: TestClient, email: str, password: str) -> dict:
    return client.post("/api/v1/auth/login", json={"email": email, "password": password})


def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@requires_pg
class TestRegistration:
    def test_register_returns_201_and_user(self, client_seeded):
        res = _register(client_seeded, USER_A)
        assert res.status_code == 201
        body = res.json()
        assert body["success"] is True
        assert body["data"]["email"] == USER_A["email"]
        assert body["data"]["role"] == "user"
        assert body["meta"]["request_id"]

    def test_password_hash_never_in_response(self, client_seeded):
        res = _register(client_seeded, USER_A)
        assert "password_hash" not in res.text
        assert "password" not in res.json()["data"]

    def test_email_normalized_to_lowercase(self, client_seeded):
        res = _register(client_seeded, {"email": "MiXeD@Test.example", "password": "password-123"})
        assert res.status_code == 201
        assert res.json()["data"]["email"] == "mixed@test.example"

    def test_duplicate_email_409(self, client_seeded):
        _register(client_seeded, USER_A)
        res = _register(client_seeded, USER_A)
        assert res.status_code == 409
        body = res.json()
        assert body["success"] is False
        assert body["error"]["code"] == "EMAIL_ALREADY_REGISTERED"

    def test_short_password_422(self, client_seeded):
        res = _register(client_seeded, {"email": "short@test.example", "password": "short"})
        assert res.status_code == 422
        assert res.json()["error"]["code"] == "VALIDATION_ERROR"

    def test_invalid_email_422(self, client_seeded):
        res = _register(client_seeded, {"email": "not-an-email", "password": "password-123"})
        assert res.status_code == 422

    def test_role_cannot_be_escalated(self, client_seeded):
        res = client_seeded.post(
            "/api/v1/auth/register",
            json={"email": "escal@test.example", "password": "password-123", "role": "admin"},
        )
        assert res.status_code == 201
        assert res.json()["data"]["role"] == "user"


@requires_pg
class TestLogin:
    def test_login_returns_token(self, client_seeded):
        _register(client_seeded, USER_A)
        res = _login(client_seeded, USER_A["email"], USER_A["password"])
        assert res.status_code == 200
        body = res.json()
        assert body["data"]["access_token"]
        assert body["data"]["token_type"] == "bearer"
        assert body["data"]["expires_in"] == get_backend_settings().jwt_expiry_s

    def test_wrong_password_401_generic(self, client_seeded):
        _register(client_seeded, USER_A)
        res = _login(client_seeded, USER_A["email"], "wrong-password")
        assert res.status_code == 401
        body = res.json()
        assert body["error"]["code"] == "INVALID_CREDENTIALS"

    def test_unknown_user_401_same_generic(self, client_seeded):
        res = _login(client_seeded, "ghost@test.example", "whatever-123")
        assert res.status_code == 401
        # same generic message as wrong password - no account disclosure
        wrong_pw = _login(client_seeded, "ghost2@test.example", "x")  # unknown too
        assert res.json()["error"]["message"] == wrong_pw.json()["error"]["message"]

    def test_inactive_user_401(self, client_seeded):
        _register(client_seeded, USER_A)
        # deactivate directly in the DB (no admin API exists for this)
        from sqlalchemy import update

        from backend.db.models import User
        from backend.db.session import get_session_factory

        with get_session_factory().begin() as session:
            session.execute(
                update(User).where(User.email == USER_A["email"]).values(is_active=False)
            )
        res = _login(client_seeded, USER_A["email"], USER_A["password"])
        assert res.status_code == 401
        assert res.json()["error"]["code"] == "INVALID_CREDENTIALS"


@requires_pg
class TestCurrentUserIdentity:
    def _token(self, client_seeded) -> str:
        _register(client_seeded, USER_A)
        return _login(client_seeded, USER_A["email"], USER_A["password"]).json()["data"][
            "access_token"
        ]

    def test_me_returns_user(self, client_seeded):
        token = self._token(client_seeded)
        res = client_seeded.get("/api/v1/auth/me", headers=_auth_headers(token))
        assert res.status_code == 200
        body = res.json()
        assert body["data"]["email"] == USER_A["email"]
        assert "password_hash" not in res.text

    def test_me_missing_token_401(self, client_seeded):
        res = client_seeded.get("/api/v1/auth/me")
        assert res.status_code == 401
        assert res.json()["error"]["code"] == "INVALID_CREDENTIALS"

    def test_me_forged_token_401(self, client_seeded):
        res = client_seeded.get("/api/v1/auth/me", headers=_auth_headers("forged.token.value"))
        assert res.status_code == 401

    def test_me_expired_token_401(self, client_seeded):
        from backend.core.jwt import create_access_token

        expired = create_access_token("11111111-2222-3333-4444-555555555555", expires_in_s=-1)
        res = client_seeded.get("/api/v1/auth/me", headers=_auth_headers(expired))
        assert res.status_code == 401
        assert res.json()["error"]["code"] == "INVALID_CREDENTIALS"

    def test_me_deactivated_user_401(self, client_seeded):
        token = self._token(client_seeded)
        from sqlalchemy import update

        from backend.db.models import User
        from backend.db.session import get_session_factory

        with get_session_factory().begin() as session:
            session.execute(
                update(User).where(User.email == USER_A["email"]).values(is_active=False)
            )
        res = client_seeded.get("/api/v1/auth/me", headers=_auth_headers(token))
        assert res.status_code == 401

    def test_me_wrong_scheme_header_401(self, client_seeded):
        token = self._token(client_seeded)
        res = client_seeded.get("/api/v1/auth/me", headers={"Authorization": f"Basic {token}"})
        assert res.status_code == 401
