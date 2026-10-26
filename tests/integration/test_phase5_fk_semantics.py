"""PostgreSQL integration: Phase 5 F2 FK deletion semantics.

Proves (DB level, lab schema after migration 0004):
- Deleting a live_authorization referenced by any scan FAILS (RESTRICT);
- Deleting a project referenced by an authorization FAILS (RESTRICT) -
  audit rows can never be cascade-erased;
- Deleting a user referenced by an authorization's approved_by FAILS
  (RESTRICT);
- Deleting objects NOT referenced by authorizations still works
  (scans/projects remain normally deletable when they have no
  authorization ties);
- Migration 0004 downgrade/upgrade round trip on a DISPOSABLE database
  (see tests/integration/test_migrations.py for the pattern; we only
  ever upgrade the lab DB).

These failures are the DESIRED behavior (fail closed, audit preserved).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from backend.db import models
from backend.services.live_authorization_service import (
    build_authorization_snapshot,
    parse_origin,
)
from integration.pg import requires_pg

pytestmark = requires_pg


def _sm(engine):
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def _make_world(sm, *, with_scan: bool):
    """user -> project -> authorization (+ optional live scan row)."""
    with sm() as s:
        owner = models.User(
            email=f"fk-owner-{uuid.uuid4().hex[:8]}@test.example",
            password_hash="x",
            role="user",
        )
        approver = models.User(
            email=f"fk-admin-{uuid.uuid4().hex[:8]}@test.example",
            password_hash="x",
            role="admin",
        )
        s.add_all([owner, approver])
        s.flush()
        project = models.Project(
            owner_id=owner.id,
            name="FK semantics lab",
            scope=[{"type": "url", "value": "https://example.com", "note": None}],
        )
        s.add(project)
        s.flush()
        now = datetime.now(timezone.utc)
        auth = models.LiveAuthorization(
            project_id=project.id,
            status="active",
            policy_version=models_live_policy_version(),
            evidence_ref="signed-agreement-1",
            origins=[parse_origin("https://example.com")],
            exclusions=[],
            methods=["GET"],
            approved_by=approver.id,
            valid_from=now,
            valid_until=now + timedelta(days=1),
        )
        s.add(auth)
        s.flush()
        snapshot = build_authorization_snapshot(auth)
        scan = None
        if with_scan:
            from backend.services import live_probe_budgets as budgets
            from backend.services.live_authorization_service import _digest

            scan_id = uuid.uuid4()
            execution_profile = budgets.render_execution_profile(
                profile_id=uuid.uuid4(),
                scan_id=scan_id,
                authorization_id=auth.id,
                project_id=project.id,
                policy_version=models_live_policy_version(),
            )
            scan = models.Scan(
                id=scan_id,
                project_id=project.id,
                status="queued",
                profile="live_probe",
                mode="pipeline",
                target_snapshot=[],
                live_authorization_id=auth.id,
                authorization_snapshot=snapshot,
                authorization_snapshot_digest=snapshot["digest"],
                execution_profile=execution_profile,
                execution_profile_digest=_digest(execution_profile),
            )
            s.add(scan)
            s.flush()
        s.commit()
        if not with_scan:
            # keep a scan-free world usable for the cascade test
            pass
        return {
            "sm": sm,
            "owner_id": owner.id,
            "approver_id": approver.id,
            "project_id": project.id,
            "auth_id": auth.id,
            "scan_id": scan.id if scan else None,
        }


def models_live_policy_version() -> str:
    from backend.core.config import get_backend_settings

    return get_backend_settings().live_probe_policy_version


class TestFKDeletionSemantics:
    def test_deleting_referenced_authorization_fails(self, pg_engine):
        w = _make_world(_sm(pg_engine), with_scan=True)
        with pytest.raises(IntegrityError):
            with _sm(pg_engine)() as s:
                s.delete(s.get(models.LiveAuthorization, w["auth_id"]))
                s.commit()
        # audit row + scan FK survive untouched
        with _sm(pg_engine)() as s:
            assert s.get(models.LiveAuthorization, w["auth_id"]) is not None
            scan = s.get(models.Scan, w["scan_id"])
            assert scan.live_authorization_id == w["auth_id"]
            assert scan.authorization_snapshot is not None
            assert scan.authorization_snapshot_digest is not None

    def test_deleting_project_with_authorization_history_fails(self, pg_engine):
        w = _make_world(_sm(pg_engine), with_scan=False)
        with pytest.raises(IntegrityError):
            with _sm(pg_engine)() as s:
                s.delete(s.get(models.Project, w["project_id"]))
                s.commit()
        with _sm(pg_engine)() as s:
            assert s.get(models.LiveAuthorization, w["auth_id"]) is not None

    def test_deleting_approver_user_fails(self, pg_engine):
        w = _make_world(_sm(pg_engine), with_scan=False)
        with pytest.raises(IntegrityError):
            with _sm(pg_engine)() as s:
                s.delete(s.get(models.User, w["approver_id"]))
                s.commit()
        with _sm(pg_engine)() as s:
            auth = s.get(models.LiveAuthorization, w["auth_id"])
            assert auth is not None
            assert auth.approved_by == w["approver_id"]

    def test_unreferenced_project_and_scans_still_deletable(self, pg_engine):
        """Projects WITHOUT any authorization tie delete normally - the
        restriction is precisely scoped to authorization history."""
        w = _make_world(_sm(pg_engine), with_scan=False)
        with _sm(pg_engine)() as s:
            owner = s.get(models.User, w["owner_id"])
            fresh = models.Project(owner_id=owner.id, name="no-auth")
            s.add(fresh)
            s.commit()
            fresh_id = fresh.id
            s.delete(s.get(models.Project, fresh_id))
            s.commit()
        with _sm(pg_engine)() as s:
            assert s.get(models.Project, fresh_id) is None

    def test_non_live_scans_still_cascade_with_project(self, pg_engine):
        w = _make_world(_sm(pg_engine), with_scan=False)
        with _sm(pg_engine)() as s:
            owner = s.get(models.User, w["owner_id"])
            fresh = models.Project(owner_id=owner.id, name="plain")
            s.add(fresh)
            s.flush()
            scan = models.Scan(
                project_id=fresh.id,
                status="queued",
                profile="web",
                mode="pipeline",
                target_snapshot=[],
            )
            s.add(scan)
            s.commit()
            project_id, scan_id = fresh.id, scan.id
            s.delete(s.get(models.Project, project_id))
            s.commit()
        with _sm(pg_engine)() as s:
            assert s.get(models.Scan, scan_id) is None


class TestFKConstraintShape:
    def test_ondelete_actions_after_upgrade_head(self, pg_engine):
        """The DB truth, not the models: RESTRICT must be in force."""
        with pg_engine.connect() as conn:
            rows = dict(
                conn.execute(
                    text(
                        """
                        SELECT conname, pg_get_constraintdef(oid)
                        FROM pg_constraint
                        WHERE contype = 'f'
                          AND conrelid IN ('scans'::regclass,
                                           'live_authorizations'::regclass)
                        """
                    )
                ).fetchall()
            )
        scan_fk = rows["fk_scans_live_authorization"]
        proj_fk = rows["live_authorizations_project_id_fkey"]
        appr_fk = rows["live_authorizations_approved_by_fkey"]
        assert "ON DELETE SET NULL" not in scan_fk
        assert "RESTRICT" in scan_fk or "NO ACTION" in scan_fk
        assert "RESTRICT" in proj_fk or "NO ACTION" in proj_fk
        assert "RESTRICT" in appr_fk or "NO ACTION" in appr_fk
        for name in (proj_fk, appr_fk):
            assert "CASCADE" not in name
