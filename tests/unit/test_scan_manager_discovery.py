"""ScanManager Phase 4C Step 4 integration tests (file SQLite, no subprocess).

Verifies the deterministic discovery pre-stage hook:
ScanManager -> DiscoveryService -> Subfinder/DNSX -> persistence,
with the promoted set staying run-local and all persistent
authorization (Project.scope, Scan.target_snapshot, Policy) unchanged.
"""
from __future__ import annotations

import ast
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agent_core.planner import ScriptedPlanner
from agent_core.safety.validator import SafetyValidator
from agent_core.schemas.actions import Finish, ToolCall
from backend.db import models  # noqa: F401
from backend.db.base import Base
from backend.db.models import Asset, Project, Scan, ToolRun, User
from backend.services.scan_manager import ScanManager


def _factory(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path}/mgr-disc.db", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def _seed(factory, *, scope=None, snapshot=None, profile="full", mode="pipeline", status="queued"):
    scope = scope if scope is not None else [{"type": "host", "value": "demo.local"}]
    snapshot = snapshot if snapshot is not None else list(scope)
    with factory() as session:
        user = User(email=f"u-{uuid.uuid4().hex[:8]}@test.example", password_hash="x", role="user")
        session.add(user)
        session.flush()
        project = Project(owner_id=user.id, name="P", scope=list(scope))
        session.add(project)
        session.flush()
        scan = Scan(
            project_id=project.id,
            status=status,
            mode=mode,
            profile=profile,
            goal="g",
            target_snapshot=list(snapshot),
            tool_timeout_s=60,
        )
        session.add(scan)
        session.commit()
        return scan.id, project.id


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


def _snapshot_of(factory, scan_id):
    with factory() as session:
        scan = session.get(Scan, scan_id)
        import copy

        return copy.deepcopy(list(scan.target_snapshot or []))


def _scope_of(factory, project_id):
    with factory() as session:
        import copy

        return copy.deepcopy(list(session.get(Project, project_id).scope or []))


def _mock_planner():
    return ScriptedPlanner(
        [
            ToolCall(tool="mock_port_scan", params={"target": "demo.local"}),
            Finish(summary="done"),
        ]
    )


class TestRegistryWiring:
    def test_per_scan_registry_has_dnsx_safe(self, tmp_path):
        import threading as _th
        import uuid as _uuid

        from backend.services.tool_runner import RunRecorder

        mgr = ScanManager(session_factory=lambda: None, runs_dir=str(tmp_path / "runs"))
        try:
            reg = mgr._build_per_scan_registry(_uuid.uuid4(), _th.Event(), RunRecorder())
            assert reg.has("subfinder")
            assert reg.has("dnsx")
            assert reg.get("subfinder").danger_level == "safe"
            assert reg.get("dnsx").danger_level == "safe"
            assert reg.get("dnsx").name == "dnsx"
        finally:
            mgr.shutdown()

    def test_no_direct_subprocess_in_scan_manager(self):
        path = Path(__file__).resolve().parents[2] / "backend" / "services" / "scan_manager.py"
        src = path.read_text(encoding="utf-8")
        tree = ast.parse(src)
        offenders = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module and "subprocess" in node.module:
                    offenders.append(f"{node.lineno}:import-subprocess")
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if "subprocess" in alias.name:
                        offenders.append(f"{node.lineno}:import-subprocess")
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            # Only flag process-spawning calls (service.run() is allowed).
            if isinstance(func, ast.Attribute) and func.attr in (
                "Popen",
                "check_output",
                "check_call",
                "system",
                "popen",
            ):
                offenders.append(f"{node.lineno}:{func.attr}")
            for kw in node.keywords:
                if kw.arg == "shell" and getattr(kw.value, "value", None) is True:
                    offenders.append(f"{node.lineno}:shell=True")
        assert offenders == []
        assert "DiscoveryService" in src
        # Tool execution must go through the registry/service, never manual argv.
        assert "import subprocess" not in src
        assert "from subprocess" not in src
        assert "Popen(" not in src

    def test_enrichment_covers_dnsx(self):
        import inspect

        from backend.services.scan_manager import ScanManager as _M

        assert "dnsx" in inspect.getsource(_M._enrich_tool_runs)


class TestDiscoveryInvocation:
    def test_invokes_at_running_stage_with_correct_context_and_cancel(self, tmp_path):
        from backend.services import scan_manager as _mod
        from backend.services.discovery_service import DiscoveryResult

        factory = _factory(tmp_path)
        domain_scope = [{"type": "domain", "value": "example.com"}]
        scan_id, _ = _seed(factory, scope=domain_scope, profile="full")
        mgr = ScanManager(
            session_factory=factory, runs_dir=str(tmp_path / "runs"), resolver=lambda h: []
        )
        captured = {}
        orig = ScanManager._run_discovery_pre_stage

        def fake(self, *, scan_id: uuid.UUID, registry, validator, cancel):
            captured["scan_id"] = scan_id
            captured["registry_tools"] = sorted(registry.names())
            captured["validator"] = validator
            captured["cancel"] = cancel
            captured["allowed_before"] = list(validator.policy.allowed_targets)
            with factory() as session:
                row = session.get(Scan, scan_id)
                captured["status_at_call"] = row.status
                captured["snapshot_at_call"] = list(row.target_snapshot or [])
            return DiscoveryResult()

        try:
            ScanManager._run_discovery_pre_stage = fake
            mgr.submit(scan_id, planner=_mock_planner())
            assert _wait_status(factory, scan_id, ("completed", "failed")) == "completed"
            assert captured["scan_id"] == scan_id
            assert "subfinder" in captured["registry_tools"]
            assert "dnsx" in captured["registry_tools"]
            assert isinstance(captured["validator"], SafetyValidator)
            assert isinstance(captured["cancel"], threading.Event)
            # Correct lifecycle point: after TX2, scan is running.
            assert captured["status_at_call"] == "running"
            assert captured["snapshot_at_call"] == domain_scope
        finally:
            ScanManager._run_discovery_pre_stage = orig
            mgr.shutdown()

    def test_discovery_receives_existing_cancel_event(self, tmp_path):
        from backend.services.discovery_service import DiscoveryResult
        from backend.services.scan_state import apply_transition

        factory = _factory(tmp_path)
        scan_id, _ = _seed(factory)
        mgr = ScanManager(
            session_factory=factory, runs_dir=str(tmp_path / "runs"), resolver=lambda h: []
        )

        class _BlockingPlanner:
            def __init__(self):
                self.entered = threading.Event()
                self.release = threading.Event()

            def decide(self, state):
                self.entered.set()
                assert self.release.wait(timeout=30)
                return Finish(summary="released")

        planner = _BlockingPlanner()
        captured = {}
        orig = ScanManager._run_discovery_pre_stage

        def fake(self, *, scan_id, registry, validator, cancel):
            captured["cancel"] = cancel
            return DiscoveryResult()

        try:
            ScanManager._run_discovery_pre_stage = fake
            mgr.submit(scan_id, planner=planner)
            assert planner.entered.wait(timeout=30)
            # The same event object passed to discovery is the worker's
            # cancellation event: signalling it stops the run.
            assert isinstance(captured["cancel"], threading.Event)
            # Mirror scan_service.cancel_scan: DB running->cancelling + signal.
            with factory() as session:
                scan = session.get(Scan, scan_id)
                apply_transition(scan, "cancelling")
                session.commit()
            assert mgr.request_cancel(scan_id) is True
            assert captured["cancel"].is_set() is True
            planner.release.set()
            assert _wait_status(factory, scan_id, ("cancelled",)) == "cancelled"
        finally:
            ScanManager._run_discovery_pre_stage = orig
            planner.release.set()
            mgr.shutdown()

    def test_no_duplicate_worker_created(self, tmp_path):
        from backend.services.discovery_service import DiscoveryResult

        factory = _factory(tmp_path)
        scan_id, _ = _seed(factory)
        mgr = ScanManager(
            session_factory=factory, runs_dir=str(tmp_path / "runs"), resolver=lambda h: []
        )
        orig = ScanManager._run_discovery_pre_stage
        calls = []

        def fake(self, *, scan_id, registry, validator, cancel):
            calls.append(scan_id)
            # Discovery must run in the same worker thread, never submit
            # new pool work: active set stays exactly one entry.
            assert len(self.active_scan_ids()) == 1
            return DiscoveryResult()

        try:
            ScanManager._run_discovery_pre_stage = fake
            mgr.submit(scan_id, planner=_mock_planner())
            # Duplicate submit is a no-op (idempotent, no second worker).
            mgr.submit(scan_id, planner=_mock_planner())
            assert _wait_status(factory, scan_id, ("completed", "failed")) == "completed"
            assert calls == [scan_id]
            assert mgr.active_scan_ids() == []
        finally:
            ScanManager._run_discovery_pre_stage = orig
            mgr.shutdown()


class TestAuthorizationInvariants:
    def test_snapshot_scope_policy_unchanged_and_promoted_run_local(self, tmp_path):
        from backend.services.discovery_service import DiscoveryResult
        from backend.services.scope_resolution import resolve_scope

        factory = _factory(tmp_path)
        scope = [{"type": "domain", "value": "example.com"}]
        scan_id, project_id = _seed(factory, scope=scope)
        mgr = ScanManager(
            session_factory=factory, runs_dir=str(tmp_path / "runs"), resolver=lambda h: []
        )
        orig = ScanManager._run_discovery_pre_stage
        before_allowed = resolve_scope(scope, resolver=lambda h: [])

        def fake(self, *, scan_id, registry, validator, cancel):
            captured_allowed = list(validator.policy.allowed_targets)
            assert captured_allowed == before_allowed
            assert list(validator.policy.allowed_targets) == before_allowed
            return DiscoveryResult(
                parents=["example.com"],
                discovered=["app.example.com"],
                dns_verified=["app.example.com"],
                promoted=["app.example.com"],
            )

        try:
            ScanManager._run_discovery_pre_stage = fake
            mgr.submit(scan_id, planner=_mock_planner())
            assert _wait_status(factory, scan_id, ("completed", "failed")) == "completed"
            assert _snapshot_of(factory, scan_id) == scope
            assert _scope_of(factory, project_id) == scope
            # Promoted stays run-local: never written to snapshot/scope.
            assert "app.example.com" not in str(_snapshot_of(factory, scan_id))
            assert "app.example.com" not in str(_scope_of(factory, project_id))
            # And never becomes persistent authorization.
            from backend.services.scope_service import target_in_scope

            assert not target_in_scope(scope, "app.example.com")
            from agent_core.safety.policy import Policy

            assert not Policy(allowed_targets=before_allowed).target_allowed("app.example.com")
        finally:
            ScanManager._run_discovery_pre_stage = orig
            mgr.shutdown()

    def test_dns_ips_and_cname_never_authorized(self, tmp_path):
        from backend.services.discovery_service import DiscoveryResult
        from backend.services.scope_resolution import resolve_scope

        factory = _factory(tmp_path)
        scope = [{"type": "domain", "value": "example.com"}]
        scan_id, project_id = _seed(factory, scope=scope)
        mgr = ScanManager(
            session_factory=factory, runs_dir=str(tmp_path / "runs"), resolver=lambda h: []
        )
        orig = ScanManager._run_discovery_pre_stage
        allowed = resolve_scope(scope, resolver=lambda h: [])

        def fake(self, *, scan_id, registry, validator, cancel):
            return DiscoveryResult(
                parents=["example.com"],
                discovered=["cdn.example.com"],
                dns_verified=[],
                promoted=[],
            )

        try:
            ScanManager._run_discovery_pre_stage = fake
            mgr.submit(scan_id, planner=_mock_planner())
            assert _wait_status(factory, scan_id, ("completed", "failed")) == "completed"
            from agent_core.safety.policy import Policy
            from agent_core.safety.validator import SafetyValidator
            from agent_core.schemas.actions import ToolCall
            from agent_core.schemas.state import AgentState
            from agent_core.tools.registry import ToolRegistry
            from agent_core.tools.nmap import NmapTool
            from agent_core.tools.httpx import HTTPXTool

            reg = ToolRegistry()
            reg.register(NmapTool(runner=lambda *a, **k: None))
            reg.register(HTTPXTool(runner=lambda *a, **k: None))
            v = SafetyValidator(reg, Policy(allowed_targets=allowed))
            st = AgentState(run_id="t", goal="g")
            # DNS answer IP and CNAME target are observations only.
            assert not v.validate(ToolCall(tool="nmap", params={"target": "192.0.2.10"}), st).accepted
            assert not v.validate(
                ToolCall(tool="httpx", params={"targets": ["https://internal.example.net/"]}), st
            ).accepted
            assert _snapshot_of(factory, scan_id) == scope
            assert _scope_of(factory, project_id) == scope
        finally:
            ScanManager._run_discovery_pre_stage = orig
            mgr.shutdown()

    def test_real_pre_stage_does_not_mutate_policy_or_snapshot(self, tmp_path):
        """End-to-end through the real DiscoveryService with stub-free
        registry would hit real binaries; instead exercise the wrapper's
        session/snapshot guards with a validator spy and a stubbed
        DiscoveryService.run that mimics the real copy semantics."""
        import copy

        import backend.services.scan_manager as _mod
        from backend.services.discovery_service import DiscoveryResult

        factory = _factory(tmp_path)
        scope = [{"type": "domain", "value": "example.com"}]
        scan_id, project_id = _seed(factory, scope=scope, status="running")
        mgr = ScanManager(
            session_factory=factory, runs_dir=str(tmp_path / "runs"), resolver=lambda h: []
        )
        try:
            from backend.services.tool_runner import RunRecorder

            recorder = RunRecorder()
            cancel = threading.Event()
            registry = mgr._build_per_scan_registry(scan_id, cancel, recorder)
            from agent_core.safety.policy import Policy
            from agent_core.safety.validator import SafetyValidator

            allowed = ["example.com"]
            policy = Policy(allowed_targets=list(allowed), max_danger="active_scan")
            validator = SafetyValidator(registry, policy)
            before = copy.deepcopy(policy.model_dump(mode="json"))

            import backend.services.discovery_service as _disc

            orig_run = _disc.DiscoveryService.run

            def fake_run(self, *, session, scan, cancel=None, state=None, run_id=None):
                # Mimic the real per-batch isolation: build the temp copy
                # the real service builds, then drop it (caller untouched).
                tmp = self._dnsx_validator(["app.example.com"])
                assert tmp.policy.allowed_targets == ["app.example.com"]
                return DiscoveryResult(promoted=["app.example.com"])

            try:
                _disc.DiscoveryService.run = fake_run
                result = mgr._run_discovery_pre_stage(
                    scan_id=scan_id, registry=registry, validator=validator, cancel=cancel
                )
            finally:
                _disc.DiscoveryService.run = orig_run
            assert result.promoted == ["app.example.com"]
            assert policy.model_dump(mode="json") == before
            assert policy.allowed_targets == allowed
            assert _snapshot_of(factory, scan_id) == scope
            assert _scope_of(factory, project_id) == scope
        finally:
            mgr.shutdown()

    def test_discovery_failure_fail_closed(self, tmp_path):
        from backend.services.discovery_service import DiscoveryResult

        factory = _factory(tmp_path)
        scope = [{"type": "domain", "value": "example.com"}]
        scan_id, project_id = _seed(factory, scope=scope)
        mgr = ScanManager(
            session_factory=factory, runs_dir=str(tmp_path / "runs"), resolver=lambda h: []
        )
        orig = ScanManager._run_discovery_pre_stage
        planner_calls = []

        class _SpyPlanner:
            def decide(self, state):
                planner_calls.append(state.step)
                return Finish(summary="pipeline still ran")

        def fake(self, *, scan_id, registry, validator, cancel):
            # Simulate an internal discovery blowup; the wrapper must
            # convert it to an empty fail-closed result, never auth.
            raise RuntimeError("dnsx exploded")

        # The wrapper catches; patch at the service level to exercise it.
        import backend.services.discovery_service as _disc

        orig_run = _disc.DiscoveryService.run

        def boom(*args, **kwargs):
            raise RuntimeError("dnsx exploded")

        try:
            _disc.DiscoveryService.run = boom
            mgr.submit(scan_id, planner=_SpyPlanner())
            assert _wait_status(factory, scan_id, ("completed", "failed")) == "completed"
            # Fail-closed: pipeline still executed, scan completed (not failed
            # by discovery), no authorization expansion.
            assert planner_calls != []
            assert _snapshot_of(factory, scan_id) == scope
            assert _scope_of(factory, project_id) == scope
        finally:
            _disc.DiscoveryService.run = orig_run
            mgr.shutdown()

    def test_cancellation_skips_pipeline(self, tmp_path):
        from backend.services.discovery_service import DiscoveryResult
        from backend.services.scan_state import apply_transition

        factory = _factory(tmp_path)
        scan_id, _ = _seed(factory, scope=[{"type": "domain", "value": "example.com"}])
        mgr = ScanManager(
            session_factory=factory, runs_dir=str(tmp_path / "runs"), resolver=lambda h: []
        )
        orig = ScanManager._run_discovery_pre_stage
        planner_calls = []

        class _SpyPlanner:
            def decide(self, state):
                planner_calls.append(1)
                return Finish(summary="should not run")

        release = threading.Event()

        class _GatePlanner:
            """Hold the worker in discovery until we flip DB to cancelling."""

            def decide(self, state):  # pragma: no cover - safety net
                planner_calls.append(1)
                return Finish(summary="should not run")

        def fake(self, *, scan_id, registry, validator, cancel):
            # Simulate production cancel: DB already cancelling + event set.
            with factory() as session:
                scan = session.get(Scan, scan_id)
                if scan.status == "running":
                    apply_transition(scan, "cancelling")
                    session.commit()
            cancel.set()
            return DiscoveryResult(status="cancelled")

        try:
            ScanManager._run_discovery_pre_stage = fake
            mgr.submit(scan_id, planner=_SpyPlanner())
            assert _wait_status(factory, scan_id, ("cancelled",), timeout=30) == "cancelled"
            assert planner_calls == []
            assert mgr.active_scan_ids() == []
        finally:
            ScanManager._run_discovery_pre_stage = orig
            mgr.shutdown()

    def test_cancel_before_discovery_prevents_execution(self, tmp_path):
        factory = _factory(tmp_path)
        scan_id, _ = _seed(factory, scope=[{"type": "domain", "value": "example.com"}])
        mgr = ScanManager(
            session_factory=factory, runs_dir=str(tmp_path / "runs"), resolver=lambda h: []
        )
        try:
            from backend.services.tool_runner import RunRecorder

            cancel = threading.Event()
            cancel.set()
            registry = mgr._build_per_scan_registry(scan_id, cancel, RunRecorder())
            from agent_core.safety.policy import Policy
            from agent_core.safety.validator import SafetyValidator

            validator = SafetyValidator(registry, Policy(allowed_targets=["example.com"]))
            result = mgr._run_discovery_pre_stage(
                scan_id=scan_id, registry=registry, validator=validator, cancel=cancel
            )
            assert result.cancelled is True
            assert result.promoted == []
        finally:
            mgr.shutdown()


class TestProfileCompatibility:
    @pytest.mark.parametrize("profile", ["recon", "web", "full"])
    def test_pipeline_profiles_still_complete(self, tmp_path, profile):
        from backend.services.discovery_service import DiscoveryResult

        factory = _factory(tmp_path)
        scan_id, _ = _seed(factory, profile=profile)
        mgr = ScanManager(
            session_factory=factory, runs_dir=str(tmp_path / "runs"), resolver=lambda h: []
        )
        orig = ScanManager._run_discovery_pre_stage

        def fake(self, *, scan_id, registry, validator, cancel):
            return DiscoveryResult()

        try:
            ScanManager._run_discovery_pre_stage = fake
            # No injected planner: real PipelinePlanner path for this profile.
            mgr.submit(scan_id)
            assert _wait_status(factory, scan_id, ("completed", "failed")) == "completed"
        finally:
            ScanManager._run_discovery_pre_stage = orig
            mgr.shutdown()

    def test_pipeline_planner_stages_unchanged(self):
        from backend.services.pipeline_planner import PipelinePlanner

        snap = [{"type": "host", "value": "demo.local"}]
        assert PipelinePlanner("recon", snap).profile == "recon"
        assert PipelinePlanner("web", snap).profile == "web"
        assert PipelinePlanner("full", snap).profile == "full"
        # Discovery adds no profile names and changes no stage order.
        from backend.services.pipeline_planner import _PROFILE_STAGES

        assert _PROFILE_STAGES == {
            "recon": ("nmap", "httpx"),
            "web": ("httpx", "nuclei"),
            "full": ("nmap", "httpx", "nuclei"),
        }

    def test_non_discovery_cidr_scan_unchanged(self, tmp_path):
        from backend.services.discovery_service import DiscoveryResult

        factory = _factory(tmp_path)
        scope = [{"type": "cidr", "value": "10.0.0.0/24"}]
        scan_id, project_id = _seed(factory, scope=scope)
        mgr = ScanManager(
            session_factory=factory, runs_dir=str(tmp_path / "runs"), resolver=lambda h: []
        )
        orig = ScanManager._run_discovery_pre_stage
        calls = []

        def fake(self, *, scan_id, registry, validator, cancel):
            calls.append(1)
            return DiscoveryResult()

        try:
            ScanManager._run_discovery_pre_stage = fake
            mgr.submit(scan_id, planner=_mock_planner())
            assert _wait_status(factory, scan_id, ("completed", "failed")) == "completed"
            assert calls == [1]
            assert _snapshot_of(factory, scan_id) == scope
            assert _scope_of(factory, project_id) == scope
            with factory() as session:
                assert session.query(Asset).filter(Asset.scan_id == scan_id).count() == 0
        finally:
            ScanManager._run_discovery_pre_stage = orig
            mgr.shutdown()

    def test_tool_execution_still_gated_by_validator(self, tmp_path):
        from backend.services.discovery_service import DiscoveryResult

        factory = _factory(tmp_path)
        scan_id, _ = _seed(factory, scope=[{"type": "domain", "value": "example.com"}])
        mgr = ScanManager(
            session_factory=factory, runs_dir=str(tmp_path / "runs"), resolver=lambda h: []
        )
        orig = ScanManager._run_discovery_pre_stage
        seen = {}

        def fake(self, *, scan_id, registry, validator, cancel):
            seen["registry"] = registry
            seen["validator"] = validator
            # The gate is intact: unknown tools raise, out-of-scope rejected.
            from agent_core.schemas.actions import ToolCall
            from agent_core.schemas.state import AgentState

            st = AgentState(run_id="t", goal="g")
            assert not validator.validate(
                ToolCall(tool="nmap", params={"target": "evil.example.com"}), st
            ).accepted
            try:
                registry.get("no_such_tool")
            except KeyError:
                seen["whitelist"] = True
            else:  # pragma: no cover
                seen["whitelist"] = False
            return DiscoveryResult()

        try:
            ScanManager._run_discovery_pre_stage = fake
            mgr.submit(scan_id, planner=_mock_planner())
            assert _wait_status(factory, scan_id, ("completed", "failed")) == "completed"
            assert seen.get("whitelist") is True
            assert seen["registry"].has("dnsx")
        finally:
            ScanManager._run_discovery_pre_stage = orig
            mgr.shutdown()
