"""Unit tests: ScanManager lifecycle on file SQLite (offline, deterministic).

Threaded paths use a file database (shared across threads); no PostgreSQL
needed. Production behavior is identical - only the session factory differs.
"""
from __future__ import annotations

import threading
import time
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agent_core.planner import ScriptedPlanner
from agent_core.schemas.actions import Finish, ToolCall
from backend.core.errors import ApiError
from backend.db import models  # noqa: F401  (registers tables)
from backend.db.base import Base
from backend.db.models import Project, Scan, User
from backend.services.scan_manager import ScanManager


def _factory(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path}/mgr.db", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def _manager(tmp_path, **overrides):
    kwargs = {"session_factory": _factory(tmp_path), "runs_dir": str(tmp_path / "runs")}
    kwargs.update(overrides)
    return ScanManager(**kwargs)


def _seed(factory, status="queued", profile="full", mode="pipeline"):
    with factory() as session:
        user = User(email=f"u-{uuid.uuid4().hex[:8]}@test.example", password_hash="x", role="user")
        session.add(user)
        session.flush()
        project = Project(owner_id=user.id, name="P", scope=[{"type": "host", "value": "demo.local"}])
        session.add(project)
        session.flush()
        scan = Scan(
            project_id=project.id, status=status, mode=mode, profile=profile,
            goal="g",
            target_snapshot=[{"type": "host", "value": "demo.local", "note": None}],
            tool_timeout_s=60,
        )
        session.add(scan)
        session.commit()
        return scan.id


def _status(factory, scan_id):
    with factory() as session:
        return session.get(Scan, scan_id).status


def _wait_status(factory, scan_id, want, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _status(factory, scan_id) in want:
            return _status(factory, scan_id)
        time.sleep(0.05)
    return _status(factory, scan_id)


def test_submit_missing_scan_404(tmp_path):
    manager = _manager(tmp_path)
    with pytest.raises(ApiError) as exc:
        manager.submit(uuid.uuid4())
    assert exc.value.code == "SCAN_NOT_FOUND"


def test_submit_non_queued_rejected(tmp_path):
    factory = _factory(tmp_path)
    scan_id = _seed(factory, status="completed")
    manager = ScanManager(session_factory=factory, runs_dir=str(tmp_path / "runs"))
    with pytest.raises(ApiError) as exc:
        manager.submit(scan_id)
    assert exc.value.code == "INTERNAL_ERROR"


def test_request_cancel_unknown_is_false(tmp_path):
    assert _manager(tmp_path).request_cancel(uuid.uuid4()) is False
    assert _manager(tmp_path).active_scan_ids() == []


def test_full_run_with_mock_planner_completes(tmp_path):
    factory = _factory(tmp_path)
    manager = ScanManager(session_factory=factory, runs_dir=str(tmp_path / "runs"))
    scan_id = _seed(factory)
    # The default registry includes the deterministic mock tools, so this
    # exercises submit -> worker -> terminal mapping end to end (offline).
    planner = ScriptedPlanner([
        ToolCall(tool="mock_port_scan", params={"target": "demo.local"}),
        Finish(summary="done"),
    ])
    manager.submit(scan_id, planner=planner)
    assert _wait_status(factory, scan_id, ("completed", "failed")) == "completed"
    assert manager.active_scan_ids() == []


def test_recover_maps_interrupted_scans(tmp_path):
    factory = _factory(tmp_path)
    ids = {
        "initializing": _seed(factory, status="initializing"),
        "running": _seed(factory, status="running"),
        "cancelling": _seed(factory, status="cancelling"),
        "queued": _seed(factory, status="queued"),
        "completed": _seed(factory, status="completed"),
    }
    out = ScanManager(
        session_factory=factory, runs_dir=str(tmp_path / "runs")
    ).recover()
    assert out == {"failed": 2, "cancelled": 1}
    assert _status(factory, ids["initializing"]) == "failed"
    assert _status(factory, ids["running"]) == "failed"
    assert _status(factory, ids["cancelling"]) == "cancelled"
    assert _status(factory, ids["queued"]) == "queued"
    assert _status(factory, ids["completed"]) == "completed"


class _BlockingPlanner:
    """Blocks in decide() until released (deterministic cancel/semaphore tests)."""

    def __init__(self):
        self.entered = threading.Event()
        self.release = threading.Event()

    def decide(self, state):
        self.entered.set()
        assert self.release.wait(timeout=30), "test did not release the planner"
        return Finish(summary="released")


def test_cancel_during_execution(tmp_path):
    from backend.services.scan_state import apply_transition

    factory = _factory(tmp_path)
    manager = ScanManager(session_factory=factory, runs_dir=str(tmp_path / "runs"))
    scan_id = _seed(factory)
    planner = _BlockingPlanner()
    manager.submit(scan_id, planner=planner)
    assert planner.entered.wait(timeout=30)
    assert _wait_status(factory, scan_id, ("running",)) == "running"
    # Mirror what scan_service.cancel_scan does for running scans.
    with factory() as session:
        scan = session.get(Scan, scan_id)
        apply_transition(scan, "cancelling")
        session.commit()
    assert manager.request_cancel(scan_id) is True
    planner.release.set()
    assert _wait_status(factory, scan_id, ("cancelled",)) == "cancelled"
    assert manager.active_scan_ids() == []


def test_semaphore_bound_and_429(tmp_path):
    factory = _factory(tmp_path)
    manager = ScanManager(
        session_factory=factory, runs_dir=str(tmp_path / "runs"), max_concurrent_scans=1
    )
    first = _seed(factory)
    second = _seed(factory)
    planner = _BlockingPlanner()
    try:
        manager.submit(first, planner=planner)
        assert planner.entered.wait(timeout=30)
        with pytest.raises(ApiError) as exc:
            manager.submit(second)
        assert exc.value.code == "TOO_MANY_SCANS"
        assert exc.value.http_status == 429
        assert _status(factory, second) == "queued"  # untouched, retryable
    finally:
        planner.release.set()
