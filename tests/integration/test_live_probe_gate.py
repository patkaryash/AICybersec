"""PostgreSQL integration: Stage-1 live_probe execution gate.

Proves the hard guarantee the API tests cannot: even a scan row
submitted DIRECTLY to the ScanManager (bypassing the API feature-flag
gate) is refused before any state transition, registry build, planner,
discovery pre-stage, or tool execution.

Covers:
- A fully valid authorization + snapshot -> refused unconditionally in
  Stage 1 ("Live probe execution is disabled..."), with ZERO tool runs.
- Tampered snapshot digest anchor -> "snapshot failed the integrity
  check" refusal.
- Tampered snapshot payload (origins edited) -> integrity refusal.
- Authorization suspended AFTER snapshot creation -> "suspended" refusal.
- F5: a scan whose live_authorization_id does NOT reference the
  authorization its snapshot identifies (swapped/copied snapshot) fails
  closed; a snapshot missing authorization_id fails closed.
"""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.orm import sessionmaker

from backend.core.errors import ApiError
from backend.db import models
from backend.services.scan_manager import ScanManager
from backend.services import live_probe_budgets as budgets
from backend.services.live_authorization_service import (
    _digest,
    _snapshot_core,
    parse_origin,
    verify_live_scan_authorization,
)
from backend.services.live_authorization_service import (
    build_authorization_snapshot,
)
from integration.pg import requires_pg

pytestmark = requires_pg

TERMINAL = ("completed", "failed", "cancelled")


def _sessionmaker(engine):
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def _world(
    engine,
    *,
    tamper_digest=None,
    tamper_origins=False,
    suspend=False,
    snapshot_from_other_auth=False,
    remove_snapshot_authorization_id=False,
):
    """Create user/project/authorization/scan rows directly and return
    (sessionmaker, scan_id).

    F5 modes:
    - ``snapshot_from_other_auth``: create a SECOND authorization and
      stamp the scan with auth B's valid snapshot + digest while the
      scan row references auth A (a cheated cross-scan copy).
    - ``remove_snapshot_authorization_id``: strip the authorization_id
      key from the snapshot, recompute its embedded digest AND set the
      digest anchor to match (attacker has full DB write access).
    """
    now = datetime.now(timezone.utc)
    sm = _sessionmaker(engine)
    with sm() as s:
        user = models.User(
            email=f"live-gate-{uuid.uuid4().hex[:8]}@test.example",
            password_hash="x",
            role="admin",
        )
        s.add(user)
        s.flush()
        project = models.Project(
            owner_id=user.id,
            name="Live lab",
            scope=[{"type": "url", "value": "https://example.com", "note": None}],
        )
        s.add(project)
        s.flush()

        def _auth(origins=("https://example.com",)):
            a = models.LiveAuthorization(
                project_id=project.id,
                status="active",
                policy_version=models_live_policy_version(),
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
        other_auth = _auth(("https://stuff.example.net",))

        snapshot = build_authorization_snapshot(auth)
        digest = snapshot["digest"]
        live_auth_id = auth.id
        if snapshot_from_other_auth:
            snapshot = build_authorization_snapshot(other_auth)
            digest = snapshot["digest"]
            # live_authorization_id STAYS auth.id: that is the cheat
        if remove_snapshot_authorization_id:
            snapshot = dict(snapshot)
            del snapshot["authorization_id"]
            snapshot["digest"] = _digest(_snapshot_core(snapshot))
            digest = snapshot["digest"]
        if tamper_origins:
            snapshot = dict(snapshot)
            snapshot["origins"] = [parse_origin("https://evil.com")]
            # digest stays the ORIGINAL: mutated payload + matching
            # external anchor -> detected as integrity failure
        scan_id = uuid.uuid4()
        execution_profile = budgets.render_execution_profile(
            profile_id=uuid.uuid4(),
            scan_id=scan_id,
            authorization_id=live_auth_id,
            project_id=project.id,
            policy_version=models_live_policy_version(),
        )
        scan = models.Scan(
            id=scan_id,
            project_id=project.id,
            status="queued",
            profile="live_probe",
            mode="pipeline",
            goal=None,
            target_snapshot=[],
            live_authorization_id=live_auth_id,
            authorization_snapshot=snapshot,
            authorization_snapshot_digest=tamper_digest if tamper_digest else digest,
            execution_profile=execution_profile,
            execution_profile_digest=_digest(execution_profile),
        )
        s.add(scan)
        s.commit()
        if suspend:
            auth.status = "suspended"
            s.commit()
    return sm, scan_id


def models_live_policy_version() -> str:
    from backend.core.config import get_backend_settings

    return get_backend_settings().live_probe_policy_version


def _run_to_terminal(sm, scan_id, tmp_path, timeout: float = 15.0):
    """Submit directly to the ScanManager (API gate bypassed) and wait
    for a terminal state. Returns (status, error)."""
    manager = ScanManager(
        session_factory=sm,
        runs_dir=str(tmp_path / "runs"),
        max_concurrent_scans=2,
    )
    try:
        manager.submit(scan_id)
        deadline = time.monotonic() + timeout
        last = None
        error = None
        while time.monotonic() < deadline:
            with sm() as s:
                scan = s.get(models.Scan, scan_id)
                last = scan.status
                error = scan.error
            if last in TERMINAL:
                return last, error
            time.sleep(0.05)
        pytest.fail(f"live_probe scan did not reach a terminal state; last={last}")
    finally:
        manager.shutdown()


class TestLiveProbeExecutionGate:
    def test_valid_authorization_still_refused_in_stage1_no_tool_runs(
        self, pg_engine, tmp_path
    ):
        sm, scan_id = _world(pg_engine)
        status, error = _run_to_terminal(sm, scan_id, tmp_path)
        assert status == "failed"
        assert error is not None
        assert "disabled in Stage 1" in error
        # NOTHING executed: no tool runs, no assets ever persisted
        with sm() as s:
            assert s.query(models.ToolRun).filter_by(scan_id=scan_id).count() == 0
            assert s.query(models.Asset).filter_by(scan_id=scan_id).count() == 0
            # never moved through initializing/running
            events = [
                e.data
                for e in (
                    s.query(models.AgentEvent).filter_by(scan_id=scan_id).all()
                )
            ]
        assert all(
            e.get("to") not in ("initializing", "running")
            for e in events
            if e.get("to") is not None
        )

    def test_tampered_digest_anchor_detected(self, pg_engine, tmp_path):
        sm, scan_id = _world(pg_engine, tamper_digest="0" * 64)
        status, error = _run_to_terminal(sm, scan_id, tmp_path)
        assert status == "failed"
        assert "Live authorization rejected" in error
        assert "integrity" in error
        with sm() as s:
            assert s.query(models.ToolRun).filter_by(scan_id=scan_id).count() == 0

    def test_tampered_snapshot_origins_detected(self, pg_engine, tmp_path):
        sm, scan_id = _world(pg_engine, tamper_origins=True)
        status, error = _run_to_terminal(sm, scan_id, tmp_path)
        assert status == "failed"
        assert "Live authorization rejected" in error
        with sm() as s:
            assert s.query(models.ToolRun).filter_by(scan_id=scan_id).count() == 0

    def test_suspension_after_snapshot_detected(self, pg_engine, tmp_path):
        sm, scan_id = _world(pg_engine, suspend=True)
        status, error = _run_to_terminal(sm, scan_id, tmp_path)
        assert status == "failed"
        assert "Live authorization rejected" in error
        assert "suspended" in error
        with sm() as s:
            assert s.query(models.ToolRun).filter_by(scan_id=scan_id).count() == 0


class TestF5NullScanReference:
    """The scan row references NOTHING (NULL live_authorization_id) while
    carrying a valid snapshot. This state cannot occur via normal column
    updates (the ck_scans_live_probe_snapshot CHECK blocks it - proven by
    the FK-semantics suite); the service-level check is defense in depth,
    exercised here with a duck-typed scan carrying verified real values."""

    def test_null_reference_rejected_service_level(self, pg_engine):
        sm, scan_id = _world(pg_engine)
        smk = _sessionmaker(pg_engine)
        with smk() as s:
            scan = s.get(models.Scan, scan_id)
            import types

            orphan = types.SimpleNamespace(
                live_authorization_id=None,
                authorization_snapshot=dict(scan.authorization_snapshot),
                authorization_snapshot_digest=scan.authorization_snapshot_digest,
                project_id=scan.project_id,
            )
            with pytest.raises(ApiError) as e:
                verify_live_scan_authorization(s, orphan)
        assert "does not reference" in e.value.message


class TestF5AuthorizationIdCrossCheck:
    """scan.live_authorization_id must equal the snapshot's
    authorization_id; missing/mismatched identifiers fail closed."""

    def _verified(self, engine, **kwargs) -> str:
        sm, scan_id = _world(engine, **kwargs)
        with sm() as s:
            scan = s.get(models.Scan, scan_id)
            with pytest.raises(ApiError):
                verify_live_scan_authorization(s, scan)
            return str(scan.id)

    def test_swapped_snapshot_rejected(self, pg_engine):
        """Valid snapshot for auth B on a scan row referencing auth A."""
        scan_id = self._verified(pg_engine, snapshot_from_other_auth=True)
        sm = _sessionmaker(pg_engine)
        with sm() as s:
            assert s.query(models.ToolRun).filter_by(scan_id=scan_id).count() == 0

    def test_missing_authorization_id_rejected(self, pg_engine):
        """Snapshot field entirely removed, digests re-forged by an
        attacker with full DB write access; still fails closed."""
        scan_id = self._verified(pg_engine, remove_snapshot_authorization_id=True)
        sm = _sessionmaker(pg_engine)
        with sm() as s:
            assert s.query(models.ToolRun).filter_by(scan_id=scan_id).count() == 0

    def test_swapped_snapshot_refused_by_manager_end_to_end(
        self, pg_engine, tmp_path
    ):
        sm, scan_id = _world(pg_engine, snapshot_from_other_auth=True)
        status, error = _run_to_terminal(sm, scan_id, tmp_path)
        assert status == "failed"
        assert "Live authorization rejected" in error
        with sm() as s:
            assert s.query(models.ToolRun).filter_by(scan_id=scan_id).count() == 0
