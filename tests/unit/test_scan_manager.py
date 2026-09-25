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


def test_submit_missing_scan_aborts_silently(tmp_path):
    """Phase 3 §7: validation moved to the worker (re-read + confirm
    queued). Submitting an unknown scan must not crash and must not
    execute anything."""
    manager = _manager(tmp_path)
    manager.submit(uuid.uuid4())  # no exception: the worker aborts
    deadline = time.time() + 5
    while time.time() < deadline and manager.active_scan_ids():
        time.sleep(0.05)
    assert manager.active_scan_ids() == []


def test_submit_non_queued_aborts_without_execution(tmp_path):
    """Phase 3 §7: a non-queued scan is aborted by the worker's re-read
    (race-safe) - never executed, never transitioned."""
    factory = _factory(tmp_path)
    scan_id = _seed(factory, status="completed")
    manager = ScanManager(session_factory=factory, runs_dir=str(tmp_path / "runs"))
    manager.submit(scan_id)  # no exception: the worker aborts
    deadline = time.time() + 5
    while time.time() < deadline and manager.active_scan_ids():
        time.sleep(0.05)
    assert manager.active_scan_ids() == []
    assert _status(factory, scan_id) == "completed"


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


class _ExplodingPlanner:
    """Simulates an unexpected worker/planner exception (failure lifecycle)."""

    def decide(self, state):
        raise RuntimeError("planner exploded")


def test_worker_exception_marks_scan_failed(tmp_path):
    """Verification evidence (review §15): an unexpected worker exception
    must become a controlled scan failure - never a scan stuck running."""
    factory = _factory(tmp_path)
    manager = ScanManager(session_factory=factory, runs_dir=str(tmp_path / "runs"))
    scan_id = _seed(factory)
    manager.submit(scan_id, planner=_ExplodingPlanner())
    assert _wait_status(factory, scan_id, ("failed", "completed", "cancelled")) == "failed"
    assert manager.active_scan_ids() == []


def test_recover_maps_interrupted_scans(tmp_path):
    """Startup recovery (locked decision): queued -> re-submitted;
    initializing/running -> failed; cancelling -> cancelled; terminal
    untouched. Idempotent."""
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
    assert out["failed"] == 2
    assert out["cancelled"] == 1
    assert out["rescheduled"] == 1
    assert _status(factory, ids["initializing"]) == "failed"
    assert _status(factory, ids["running"]) == "failed"
    assert _status(factory, ids["cancelling"]) == "cancelled"
    assert _status(factory, ids["completed"]) == "completed"
    # the queued scan was re-scheduled: it leaves the queued state
    assert _wait_status(factory, ids["queued"], ("completed", "failed")) in (
        "completed",
        "failed",
    )


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


def test_pool_queues_when_saturated(tmp_path):
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
        # Phase 3 §8: saturation NEVER rejects a scan - the second waits
        # in the pool queue (FIFO) and runs when a worker frees.
        manager.submit(second)  # no 429, no exception
        assert _status(factory, second) == "queued"  # waiting in the queue
        planner.release.set()  # free the worker -> the queued scan runs
        assert _wait_status(factory, first, ("completed", "failed")) == "completed"
        assert _wait_status(factory, second, ("completed", "failed")) in (
            "completed",
            "failed",
        )
        assert manager.active_scan_ids() == []
    finally:
        planner.release.set()
