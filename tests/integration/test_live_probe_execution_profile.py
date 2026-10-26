"""PostgreSQL integration: Phase 5 Stage 2 (S2-2) execution profile.

Covers the §10 matrix rows that need a real database, on a disposable /
controlled row basis with NO network I/O:

- T03 PG: live rows are DB-gated - a live_probe scan row can never be
  INSERTed / UPDATEd without a non-null execution_profile +
  execution_profile_digest (ck_scans_live_probe_snapshot, migration
  0005); the service itself refuses a missing profile explicitly.
- T05 PG: direct SQL tamper (stale digest) -> preflight refusal,
  end-to-end via the ScanManager with zero tool runs.
- T06 PG: profile/scan cross-assignment (A-scan / B-profile) -> fail
  closed on the §4.3 binding rules, NOT on the digest.
- T38 PG: coordinated re-forge - recomputed digests everywhere but
  wrong scan/authorization/project bindings -> still fails on the
  binding rules (digest is consistency evidence only, never
  authorization).
- End-to-end invariant: after all of this, live_probe scans are STILL
  refused before tool setup and any network activity (zero sockets, no
  planner/discovery/registry work, no initializing/running moves).
"""
from __future__ import annotations

import json
import types
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from backend.core.errors import ApiError
from backend.db import models
from backend.services import live_probe_budgets as budgets
from backend.services.live_authorization_service import (
    _digest,
    build_authorization_snapshot,
    parse_origin,
    verify_live_scan_authorization,
)
from integration.pg import requires_pg
from integration.test_live_probe_gate import (
    TERMINAL,
    _run_to_terminal,
)

pytestmark = requires_pg


def _sm(engine):
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def _policy_version() -> str:
    from backend.core.config import get_backend_settings

    return get_backend_settings().live_probe_policy_version


def _make_profile(scan_id, auth_id, project_id):
    payload = budgets.render_execution_profile(
        profile_id=uuid.uuid4(),
        scan_id=scan_id,
        authorization_id=auth_id,
        project_id=project_id,
        policy_version=_policy_version(),
    )
    return payload, _digest(payload)


def _world(engine):
    """user -> project -> auth A -> auth B -> live scan with a VALID
    execution profile (direct row creation, API gate bypassed)."""
    now = datetime.now(timezone.utc)
    smk = _sm(engine)
    with smk() as s:
        user = models.User(
            email=f"t22-{uuid.uuid4().hex[:8]}@test.example",
            password_hash="x",
            role="admin",
        )
        s.add(user)
        s.flush()
        project = models.Project(
            owner_id=user.id,
            name="Execution profile lab",
            scope=[{"type": "url", "value": "https://example.com", "note": None}],
        )
        s.add(project)
        s.flush()

        def _auth(origins=("https://example.com",)):
            a = models.LiveAuthorization(
                project_id=project.id,
                status="active",
                policy_version=_policy_version(),
                evidence_ref="signed-agreement-1",
                origins=[parse_origin(o) for o in origins],
                exclusions=[],
                methods=["GET"],
                approved_by=user.id,
                valid_from=now - timedelta(days=1),
                valid_until=now + timedelta(days=30),
            )
            s.add(a)
            s.flush()
            return a

        auth = _auth()
        other_auth = _auth(("https://other.example.net",))
        snapshot = build_authorization_snapshot(auth)
        scan_id = uuid.uuid4()
        profile_payload, profile_digest = _make_profile(scan_id, auth.id, project.id)
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
            execution_profile=profile_payload,
            execution_profile_digest=profile_digest,
        )
        s.add(scan)
        s.commit()
    return smk, scan_id, str(auth.id), str(other_auth.id), str(project.id)


def _rewrite_profile(engine, scan_id, payload, digest) -> None:
    """Coordinated DB-side rewrite of the two profile anchors (attacker
    with full DB write access; digest recomputation included)."""
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE scans SET execution_profile = CAST(:p AS jsonb), "
                "execution_profile_digest = :d WHERE id = :id"
            ),
            {"p": json.dumps(payload), "d": digest, "id": scan_id},
        )


def _tamper_budget_at_db(engine, scan_id, field: str, new_value: str) -> None:
    """Direct SQL tamper: payload edit only; the digest anchor stays
    stale (consistency anchor must catch it)."""
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE scans SET execution_profile = JSONB_SET("
                f"execution_profile, '{{budgets,{field}}}', '{new_value}') "
                "WHERE id = :id"
            ),
            {"id": scan_id},
        )


def _reforge_profile(engine, scan_id, *, mutate=None, target_scan_id=None,
                     target_auth_id=None, target_project_id=None):
    """Fetch the scan's profile, mutate payload + recompute digest and
    write BOTH the payload and the digest anchor back (a coherent
    re-forge the digest alone can never catch)."""
    smk = _sm(engine)
    with smk() as s:
        scan = s.get(models.Scan, scan_id)
        payload = dict(scan.execution_profile)
        payload["scan_id"] = str(target_scan_id or payload["scan_id"])
        payload["authorization_id"] = str(target_auth_id or payload["authorization_id"])
        payload["project_id"] = str(target_project_id or payload["project_id"])
        if mutate:
            mutate(payload)
        digest = _digest(payload)
    _rewrite_profile(engine, scan_id, payload, digest)


class TestT03PreMigrationRows:
    def test_insert_live_scan_without_profile_blocked_by_check(self, pg_engine):
        """DB truth (migration 0005): a live_probe row can never exist
        without its execution profile + digest anchor."""
        now = datetime.now(timezone.utc)
        smk = _sm(pg_engine)
        with smk() as s:
            user = models.User(
                email=f"t03-{uuid.uuid4().hex[:8]}@test.example",
                password_hash="x",
                role="admin",
            )
            s.add(user)
            s.flush()
            project = models.Project(owner_id=user.id, name="T03")
            s.add(project)
            s.flush()
            auth = models.LiveAuthorization(
                project_id=project.id,
                status="active",
                policy_version=_policy_version(),
                evidence_ref="e",
                origins=[parse_origin("https://example.com")],
                exclusions=[],
                methods=["GET"],
                approved_by=user.id,
                valid_from=now - timedelta(days=1),
                valid_until=now + timedelta(days=30),
            )
            s.add(auth)
            s.flush()
            snapshot = build_authorization_snapshot(auth)
            scan = models.Scan(
                project_id=project.id,
                status="queued",
                profile="live_probe",
                mode="pipeline",
                target_snapshot=[],
                live_authorization_id=auth.id,
                authorization_snapshot=snapshot,
                authorization_snapshot_digest=snapshot["digest"],
                # NO execution_profile / digest: pre-migration shape
            )
            s.add(scan)
            with pytest.raises(IntegrityError):
                s.commit()

    def test_nulling_profile_at_db_blocked_by_check(self, pg_engine):
        smk, scan_id, *_ = _world(pg_engine)
        with pg_engine.begin() as conn:
            with pytest.raises(IntegrityError):
                conn.execute(
                    text(
                        "UPDATE scans SET execution_profile = NULL, "
                        "execution_profile_digest = NULL WHERE id = :id"
                    ),
                    {"id": scan_id},
                )

    def test_missing_profile_refused_explicitly_service_level(self, pg_engine):
        """Pre-migration queued rows (no profile) fail closed with the
        explicit 'execution profile missing' refusal."""
        smk, scan_id, *_ = _world(pg_engine)
        with smk() as s:
            scan = s.get(models.Scan, scan_id)
            pre_migration = types.SimpleNamespace(
                id=scan.id,
                project_id=scan.project_id,
                live_authorization_id=scan.live_authorization_id,
                authorization_snapshot=dict(scan.authorization_snapshot),
                authorization_snapshot_digest=scan.authorization_snapshot_digest,
                execution_profile=None,
                execution_profile_digest=None,
            )
            with pytest.raises(ApiError) as e:
                verify_live_scan_authorization(s, pre_migration)
        assert "Execution profile missing" in e.value.message


class TestT05DatabaseTamper:
    def test_sql_tamper_with_stale_digest_refused_by_service(self, pg_engine):
        smk, scan_id, *_ = _world(pg_engine)
        _tamper_budget_at_db(pg_engine, scan_id, "wall_clock_s", "999999")
        with smk() as s:
            scan = s.get(models.Scan, scan_id)
            with pytest.raises(ApiError) as e:
                verify_live_scan_authorization(s, scan)
        assert "integrity" in e.value.message

    def test_sql_tamper_refused_end_to_end_zero_tools(self, pg_engine, tmp_path):
        smk, scan_id, *_ = _world(pg_engine)
        _tamper_budget_at_db(pg_engine, scan_id, "max_requests_per_scan", "100000")
        status, error = _run_to_terminal(smk, scan_id, tmp_path)
        assert status == "failed"
        assert "Live authorization rejected" in error
        assert "integrity" in error
        with smk() as s:
            assert s.query(models.ToolRun).filter_by(scan_id=scan_id).count() == 0
            assert s.query(models.Asset).filter_by(scan_id=scan_id).count() == 0


class TestT06CrossAssignment:
    def test_profile_points_at_other_authorization_fails_on_binding(self, pg_engine):
        """A-scan / B-profile cross-assignment with the profile digest
        RECOMPUTED: only the binding rules can catch it (not the
        digest)."""
        smk, scan_id, auth_id, other_auth_id, project_id = _world(pg_engine)
        assert other_auth_id != auth_id
        _reforge_profile(
            pg_engine, scan_id, target_auth_id=uuid.UUID(other_auth_id)
        )
        with smk() as s:
            scan = s.get(models.Scan, scan_id)
            with pytest.raises(ApiError) as e:
                verify_live_scan_authorization(s, scan)
        assert "authorization_id does not match" in e.value.message
        assert "integrity" not in e.value.message

    def test_cross_assignment_refused_end_to_end(self, pg_engine, tmp_path):
        smk, scan_id, auth_id, other_auth_id, project_id = _world(pg_engine)
        _reforge_profile(
            pg_engine, scan_id, mutate=None, target_auth_id=uuid.UUID(other_auth_id)
        )
        status, error = _run_to_terminal(smk, scan_id, tmp_path)
        assert status == "failed"
        assert "Live authorization rejected" in error
        with smk() as s:
            assert s.query(models.ToolRun).filter_by(scan_id=scan_id).count() == 0


class TestT38CoordinatedReforge:
    def test_reforged_bindings_fail_on_binding_rules_not_digest(self, pg_engine):
        """The core §4.3 demo: full-DB-write attacker rewrites
        scan/authorization/project bindings and recomputes the profile
        digest consistently. Digest holds; the BINDING rules fail."""
        smk, scan_id, *_ = _world(pg_engine)

        def _swap(payload):
            payload["scan_id"] = str(uuid.uuid4())
            payload["authorization_id"] = str(uuid.uuid4())
            payload["project_id"] = str(uuid.uuid4())

        _reforge_profile(pg_engine, scan_id, mutate=_swap)
        with smk() as s:
            scan = s.get(models.Scan, scan_id)
            with pytest.raises(ApiError) as e:
                verify_live_scan_authorization(s, scan)
        assert "Execution profile does not bind" in e.value.message
        assert "integrity" not in e.value.message
        with smk() as s:
            assert s.query(models.ToolRun).filter_by(scan_id=scan_id).count() == 0

    def test_reforged_scan_id_only_fails_on_binding(self, pg_engine):
        smk, scan_id, *_ = _world(pg_engine)
        _reforge_profile(pg_engine, scan_id, target_scan_id=uuid.uuid4())
        with smk() as s:
            scan = s.get(models.Scan, scan_id)
            with pytest.raises(ApiError) as e:
                verify_live_scan_authorization(s, scan)
        assert "scan_id does not match" in e.value.message
        assert "integrity" not in e.value.message

    def test_reforged_project_id_only_fails_on_binding(self, pg_engine):
        smk, scan_id, *_ = _world(pg_engine)
        _reforge_profile(pg_engine, scan_id, target_project_id=uuid.uuid4())
        with smk() as s:
            scan = s.get(models.Scan, scan_id)
            with pytest.raises(ApiError) as e:
                verify_live_scan_authorization(s, scan)
        assert "project_id does not match" in e.value.message
        assert "integrity" not in e.value.message


class TestValidProfileVerifies:
    def test_valid_profile_and_snapshot_verify_cleanly(self, pg_engine):
        """Positive control: issuance-time profiles verify through the
        full Stage 1 + Stage 2 preflight."""
        smk, scan_id, *_ = _world(pg_engine)
        with smk() as s:
            scan = s.get(models.Scan, scan_id)
            verified = verify_live_scan_authorization(s, scan)
            assert verified["authorization_id"] == scan.live_authorization_id
            assert scan.execution_profile["steps"] == ["live_root_get"]
            assert scan.execution_profile["executor"] == "live_transport_v1"
            assert scan.execution_profile["dns_policy"]["record_groups"] == ["A", "AAAA"]
            assert scan.execution_profile_digest == _digest(scan.execution_profile)


class TestLiveStillRefusedAfterS22:
    """S2-2 invariant: after adding the profile contract, live_probe
    scans STILL refuse unconditionally BEFORE tool setup and any
    network activity (zero sockets, no planner, no discovery, no
    registry, no initializing/running moves)."""

    def test_valid_profile_scan_still_refused_stage1(self, pg_engine, tmp_path):
        smk, scan_id, *_ = _world(pg_engine)
        status, error = _run_to_terminal(smk, scan_id, tmp_path)
        assert status == "failed"
        assert "disabled in Stage 1" in error
        with smk() as s:
            assert s.query(models.ToolRun).filter_by(scan_id=scan_id).count() == 0
            assert s.query(models.Asset).filter_by(scan_id=scan_id).count() == 0
            events = [
                e.data
                for e in s.query(models.AgentEvent).filter_by(scan_id=scan_id).all()
            ]
        assert all(
            e.get("to") not in ("initializing", "running")
            for e in events
            if e.get("to") is not None
        )

    def test_forged_profile_scan_still_refused_no_tools(self, pg_engine, tmp_path):
        smk, scan_id, *_ = _world(pg_engine)
        _reforge_profile(
            pg_engine,
            scan_id,
            mutate=lambda p: p["budgets"].__setitem__("max_requests_per_scan", 999_999),
        )
        status, error = _run_to_terminal(smk, scan_id, tmp_path)
        assert status == "failed"
        assert "Live authorization rejected" in error
        with smk() as s:
            assert s.query(models.ToolRun).filter_by(scan_id=scan_id).count() == 0
