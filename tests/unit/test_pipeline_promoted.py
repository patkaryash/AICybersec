"""Phase 4C Step 5: PipelinePlanner promoted-set -> HTTPX only (no subprocess).

Planner unit tests are pure (no DB); ScanManager wiring tests use file
SQLite with mocked discovery (no real Subfinder/DNSX) and real
PipelinePlanner path. HTTPX/nmap binaries are absent so tool executions
fail fast; ToolRun.parameters (proposed params persisted by the sink)
prove which targets reached which stage.
"""
from __future__ import annotations

import ast
import copy
import threading
import time
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agent_core.safety.policy import Policy
from agent_core.safety.validator import SafetyValidator
from agent_core.schemas.actions import Finish, ToolCall
from agent_core.schemas.results import Observation
from agent_core.schemas.state import AgentState
from backend.db import models  # noqa: F401
from backend.db.base import Base
from backend.db.models import Asset, Project, Scan, ToolRun, User
from backend.services.pipeline_planner import (
    MAX_STAGE_TARGETS,
    PipelinePlanner,
    sanitize_promoted_hosts,
)
from backend.services.scan_manager import ScanManager


DOMAIN_SNAP = [{"type": "domain", "value": "example.com"}]
MIXED_SNAP = [
    {"type": "domain", "value": "example.com"},
    {"type": "host", "value": "demo.local"},
]


def _state(observations=None, step=0, max_steps=12):
    return AgentState(
        run_id="t", goal="g", max_steps=max_steps, step=step,
        observations=list(observations or []),
    )


def _obs(tool, data=None, source="tool", ok=True):
    return Observation(
        step=1, source=source, tool=tool, ok=ok,
        summary="s", data=data or {}, findings=[],
    )


# ---------------------------------------------------------------- planner
class TestSanitizer:
    def test_promoted_survives_and_sorted(self):
        out = sanitize_promoted_hosts(
            ["z.example.com", "a.example.com", "a.example.com"], DOMAIN_SNAP
        )
        assert out == ["a.example.com", "z.example.com"]

    def test_non_descendant_dropped(self):
        out = sanitize_promoted_hosts(
            ["app.example.com", "evil.com", "example.com.evil.com", "evil-example.com"],
            DOMAIN_SNAP,
        )
        assert out == ["app.example.com"]

    def test_ip_url_wildcard_malformed_dropped(self):
        out = sanitize_promoted_hosts(
            [
                "192.0.2.10",
                "2001:db8::1",
                "http://app.example.com",
                "https://app.example.com/x",
                "*.example.com",
                "",
                None,
                123,
                "not a host!",
                "a" * 300 + ".example.com",
            ],
            DOMAIN_SNAP,
        )
        assert out == []

    def test_cname_outside_parent_dropped(self):
        assert sanitize_promoted_hosts(["internal.example.net"], DOMAIN_SNAP) == []

    def test_redirect_like_dropped(self):
        assert sanitize_promoted_hosts(["https://evil.com/path"], DOMAIN_SNAP) == []

    def test_non_list_returns_empty(self):
        assert sanitize_promoted_hosts(None, DOMAIN_SNAP) == []
        assert sanitize_promoted_hosts("app.example.com", DOMAIN_SNAP) == []
        assert sanitize_promoted_hosts({}, DOMAIN_SNAP) == []

    def test_snapshot_not_mutated(self):
        snap = copy.deepcopy(DOMAIN_SNAP)
        sanitize_promoted_hosts(["app.example.com", "evil.com"], snap)
        assert snap == DOMAIN_SNAP

    def test_multiple_parents(self):
        snap = [
            {"type": "domain", "value": "example.com"},
            {"type": "domain", "value": "other.test"},
        ]
        out = sanitize_promoted_hosts(
            ["a.example.com", "b.other.test", "c.unrelated.io"], snap
        )
        assert out == sorted(["a.example.com", "b.other.test"])

    def test_capped_and_deterministic(self):
        many = [f"h{i:03d}.example.com" for i in range(200)]
        out = sanitize_promoted_hosts(many, DOMAIN_SNAP)
        assert out == sorted(out)
        assert len(out) <= 50
        # Deterministic rerun.
        assert sanitize_promoted_hosts(many, DOMAIN_SNAP) == out


class TestPlannerHttpx:
    def test_promoted_reaches_httpx_domain_only(self):
        planner = PipelinePlanner("web", DOMAIN_SNAP, discovered_hosts=["app.example.com"])
        d = planner.decide(_state())
        assert isinstance(d, ToolCall) and d.tool == "httpx"
        assert d.params["targets"] == ["http://app.example.com"]

    def test_promoted_merged_after_base(self):
        # web profile: seeds from url entries first, promoted appended after.
        d = PipelinePlanner(
            "web",
            [{"type": "url", "value": "http://demo.local:8080/x"}],
            discovered_hosts=["sub.demo.local"],
        ).decide(_state())
        assert isinstance(d, ToolCall) and d.tool == "httpx"
        assert d.params["targets"][0] == "http://demo.local:8080/x"
        assert "http://sub.demo.local" in d.params["targets"]

    def test_non_promoted_candidate_absent(self):
        planner = PipelinePlanner("web", DOMAIN_SNAP, discovered_hosts=["app.example.com"])
        d = planner.decide(_state())
        assert "evil.com" not in str(d.params["targets"])
        assert "example.com.evil.com" not in str(d.params["targets"])

    def test_dns_ip_never_becomes_httpx_target(self):
        planner = PipelinePlanner("web", DOMAIN_SNAP, discovered_hosts=["192.0.2.10"])
        assert planner.discovered_hosts == []
        d = planner.decide(_state())
        assert isinstance(d, Finish)  # domain-only + no valid promoted -> Finish

    def test_malformed_never_reaches_httpx(self):
        planner = PipelinePlanner(
            "web", DOMAIN_SNAP, discovered_hosts=["*.example.com", "http://x", ""]
        )
        assert planner.discovered_hosts == []

    def test_duplicates_deduped_and_capped(self):
        planner = PipelinePlanner(
            "web",
            DOMAIN_SNAP,
            discovered_hosts=["app.example.com", "APP.EXAMPLE.COM.", "app.example.com"],
        )
        assert planner.discovered_hosts == ["app.example.com"]
        d = planner.decide(_state())
        assert d.params["targets"].count("http://app.example.com") == 1
        assert len(d.params["targets"]) <= MAX_STAGE_TARGETS

    def test_order_deterministic(self):
        hosts = ["z.example.com", "m.example.com", "a.example.com"]
        first = PipelinePlanner("web", DOMAIN_SNAP, discovered_hosts=hosts).decide(_state())
        second = PipelinePlanner("web", DOMAIN_SNAP, discovered_hosts=list(reversed(hosts))).decide(
            _state()
        )
        assert first.params["targets"] == second.params["targets"]

    def test_empty_promoted_preserves_behavior(self):
        snap = [{"type": "host", "value": "demo.local"}]
        assert (
            PipelinePlanner("web", snap).decide(_state()).params["targets"]
            == PipelinePlanner("web", snap, discovered_hosts=[]).decide(_state()).params["targets"]
        )

    def test_nmap_never_receives_promoted(self):
        planner = PipelinePlanner("full", MIXED_SNAP, discovered_hosts=["app.example.com"])
        d1 = planner.decide(_state())
        assert isinstance(d1, ToolCall) and d1.tool == "nmap"
        assert "app.example.com" not in d1.params["target"]
        # Nmap stage targets helper also excludes promoted.
        assert "app.example.com" not in planner._stage_targets("nmap", _state())

    def test_nuclei_never_receives_promoted_directly(self):
        planner = PipelinePlanner("web", DOMAIN_SNAP, discovered_hosts=["app.example.com"])
        d = planner.decide(_state([_obs("httpx", data={})]))
        assert isinstance(d, ToolCall) and d.tool == "nuclei"
        assert "app.example.com" not in str(d.params["targets"])

    def test_nuclei_chains_via_httpx_observations(self):
        planner = PipelinePlanner("web", DOMAIN_SNAP, discovered_hosts=["app.example.com"])
        httpx_obs = _obs(
            "httpx",
            data={"services": [{"url": "http://app.example.com", "final_url": "http://app.example.com", "status_code": 200}]},
        )
        d = planner.decide(_state([httpx_obs]))
        # Pre-existing chaining picks up the httpx-observed URL (justified).
        assert isinstance(d, ToolCall) and d.tool == "nuclei"
        assert d.params["targets"] == ["http://app.example.com"]

    def test_recon_full_compatible_with_promoted(self):
        for profile in ("recon", "web", "full"):
            planner = PipelinePlanner(profile, MIXED_SNAP, discovered_hosts=["app.example.com"])
            d = planner.decide(_state())
            assert isinstance(d, ToolCall)

    def test_cidr_only_still_finishes(self):
        cidr = [{"type": "cidr", "value": "10.0.0.0/24"}]
        assert isinstance(PipelinePlanner("full", cidr).decide(_state()), Finish)
        # Promoted with no name parents cannot survive the descendant gate.
        assert isinstance(
            PipelinePlanner("full", cidr, discovered_hosts=["app.example.com"]).decide(_state()),
            Finish,
        )

    def test_no_subprocess_in_planner(self):
        src = Path(__file__).resolve().parents[2] / "backend" / "services" / "pipeline_planner.py"
        text = src.read_text(encoding="utf-8")
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and "subprocess" in node.module:
                raise AssertionError("subprocess import in planner")
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert "subprocess" not in alias.name
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr not in ("Popen", "check_output", "check_call", "system", "popen")
        assert "import subprocess" not in text
        assert "Popen(" not in text

    def test_narrow_gate_httpx_only(self):
        """Promoted host: HTTPX accepted via narrow gate; Nmap/Nuclei/
        general calls stay rejected unless independently authorized."""
        from agent_core.tools.httpx import HTTPXTool
        from agent_core.tools.nmap import NmapTool
        from agent_core.tools.nuclei import NucleiTool
        from agent_core.tools.registry import ToolRegistry
        from backend.services.httpx_eligibility import PromotedHttpxValidator

        promoted = ["app.example.com"]
        planner = PipelinePlanner("web", DOMAIN_SNAP, discovered_hosts=promoted)
        d = planner.decide(_state())
        assert isinstance(d, ToolCall) and d.tool == "httpx"

        def _base(allowed):
            reg = ToolRegistry()
            reg.register(HTTPXTool(runner=lambda *a, **k: None))
            reg.register(NmapTool(runner=lambda *a, **k: None))
            reg.register(NucleiTool(runner=lambda *a, **k: None))
            return SafetyValidator(reg, Policy(allowed_targets=list(allowed)))

        st = _state()
        base = _base(["example.com"])
        assert not base.validate(d, st).accepted  # snapshot-only rejects promoted
        narrow = PromotedHttpxValidator(base=base, eligible_hosts=promoted)
        assert narrow.validate(d, st).accepted  # HTTPX-only rescue
        # Same promoted host via any other tool stays rejected.
        assert not narrow.validate(
            ToolCall(tool="nmap", params={"target": "app.example.com"}), st
        ).accepted
        assert not narrow.validate(
            ToolCall(tool="nuclei", params={"targets": ["http://app.example.com"]}), st
        ).accepted
        assert not narrow.validate(
            ToolCall(tool="nmap", params={"target": "app.example.com", "ports": "80", "profile": "safe"}),
            st,
        ).accepted
        # Original objects untouched.
        assert base.policy.allowed_targets == ["example.com"]
        assert narrow.policy is base.policy
        # Independently authorized host still passes every tool.
        assert narrow.validate(
            ToolCall(tool="nmap", params={"target": "example.com"}), st
        ).accepted

    def test_narrow_gate_multiple_and_schema_safety(self):
        from agent_core.tools.httpx import HTTPXTool
        from agent_core.tools.nmap import NmapTool
        from agent_core.tools.registry import ToolRegistry
        from backend.services.httpx_eligibility import PromotedHttpxValidator

        reg = ToolRegistry()
        reg.register(HTTPXTool(runner=lambda *a, **k: None))
        reg.register(NmapTool(runner=lambda *a, **k: None))
        base = SafetyValidator(reg, Policy(allowed_targets=["example.com"]))
        narrow = PromotedHttpxValidator(
            base=base, eligible_hosts=["b.example.com", "a.example.com", "b.example.com"]
        )
        st = _state()
        assert narrow.validate(
            ToolCall(tool="httpx", params={"targets": ["http://a.example.com"]}), st
        ).accepted
        assert narrow.validate(
            ToolCall(tool="httpx", params={"targets": ["http://b.example.com"]}), st
        ).accepted
        # Schema violations are never rescued.
        assert not narrow.validate(ToolCall(tool="httpx", params={"targets": []}), st).accepted
        assert not narrow.validate(
            ToolCall(tool="httpx", params={"targets": ["-json"]}), st
        ).accepted
        # Mixed bundle with one unauthorized host stays rejected.
        assert not narrow.validate(
            ToolCall(
                tool="httpx",
                params={"targets": ["http://a.example.com", "https://evil.com"]},
            ),
            st,
        ).accepted
        # Unknown tool stays rejected.
        assert not narrow.validate(
            ToolCall(tool="nope", params={"targets": ["http://a.example.com"]}), st
        ).accepted

    def test_redirect_targets_not_authorized(self):
        """HTTPX final_url observations never authorize Nuclei targets."""
        from agent_core.tools.httpx import HTTPXTool
        from agent_core.tools.nuclei import NucleiTool
        from agent_core.tools.registry import ToolRegistry
        from backend.services.httpx_eligibility import PromotedHttpxValidator

        reg = ToolRegistry()
        reg.register(HTTPXTool(runner=lambda *a, **k: None))
        reg.register(NucleiTool(runner=lambda *a, **k: None))
        base = SafetyValidator(reg, Policy(allowed_targets=["authorized.example.com"]))
        narrow = PromotedHttpxValidator(base=base, eligible_hosts=["app.example.com"])
        st = _state()
        # Cross-domain redirect -> rejected for nuclei (and httpx).
        assert not narrow.validate(
            ToolCall(tool="nuclei", params={"targets": ["https://evil.example.net/"]}), st
        ).accepted
        assert not narrow.validate(
            ToolCall(tool="httpx", params={"targets": ["https://evil.example.net/"]}), st
        ).accepted
        # Unauthorized hostname redirect -> rejected.
        assert not narrow.validate(
            ToolCall(tool="nuclei", params={"targets": ["http://other.io/"]}), st
        ).accepted
        # Already-authorized hostname remains compatible for both tools.
        assert narrow.validate(
            ToolCall(tool="nuclei", params={"targets": ["https://authorized.example.com/"]}), st
        ).accepted
        assert narrow.validate(
            ToolCall(tool="httpx", params={"targets": ["https://authorized.example.com/"]}), st
        ).accepted
        # Planner may still propose the redirect URL (existing chaining);
        # the gate underneath rejects it — propose/reject is the fail-closed pattern.
        planner = PipelinePlanner("web", [{"type": "host", "value": "authorized.example.com"}])
        evil_obs = _obs(
            "httpx",
            data={"services": [{"url": "http://authorized.example.com", "final_url": "https://evil.example.net/", "status_code": 200}]},
        )
        d = planner.decide(_state([evil_obs]))
        assert isinstance(d, ToolCall) and d.tool == "nuclei"
        assert "evil.example.net" in str(d.params["targets"])
        assert not narrow.validate(d, st).accepted


# ------------------------------------------------------- ScanManager wiring
def _factory(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path}/mgr-promoted.db", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def _seed(factory, *, scope, profile="web", mode="pipeline"):
    with factory() as session:
        user = User(email=f"u-{uuid.uuid4().hex[:8]}@test.example", password_hash="x", role="user")
        session.add(user)
        session.flush()
        project = Project(owner_id=user.id, name="P", scope=list(scope))
        session.add(project)
        session.flush()
        scan = Scan(
            project_id=project.id, status="queued", mode=mode, profile=profile,
            goal="g", target_snapshot=list(scope), tool_timeout_s=60,
        )
        session.add(scan)
        session.commit()
        return scan.id, project.id


def _wait(factory, scan_id, want=("completed", "failed", "cancelled"), timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with factory() as session:
            status = session.get(Scan, scan_id).status
        if status in want:
            return status
        time.sleep(0.05)
    with factory() as session:
        return session.get(Scan, scan_id).status


def _tool_targets(factory, scan_id, tool):
    with factory() as session:
        rows = (
            session.query(ToolRun)
            .filter(ToolRun.scan_id == scan_id, ToolRun.tool == tool)
            .order_by(ToolRun.created_at)
            .all()
        )
        return [list(r.parameters.get("targets", [])) for r in rows]


class TestScanManagerWiring:
    def test_only_promoted_not_discovered_reaches_planner(self, tmp_path):
        from backend.services.discovery_service import DiscoveryResult
        import backend.services.scan_manager as _mgr_mod

        factory = _factory(tmp_path)
        scope = list(DOMAIN_SNAP)
        scan_id, project_id = _seed(factory, scope=scope, profile="web")
        mgr = ScanManager(session_factory=factory, runs_dir=str(tmp_path / "runs"), resolver=lambda h: [])
        seen = {}
        orig_pre = ScanManager._run_discovery_pre_stage
        orig_planner = _mgr_mod.PipelinePlanner

        def fake_pre(self, *, scan_id, registry, validator, cancel):
            return DiscoveryResult(
                parents=["example.com"],
                discovered=["app.example.com", "unverified.example.com"],
                dns_verified=["app.example.com"],
                promoted=["app.example.com"],
            )

        class _SpyPlanner(orig_planner):
            def __init__(self, profile, snapshot, max_steps=12, discovered_hosts=None):
                seen["discovered_hosts"] = list(discovered_hosts or [])
                super().__init__(profile, snapshot, max_steps=max_steps, discovered_hosts=discovered_hosts)

        try:
            ScanManager._run_discovery_pre_stage = fake_pre
            _mgr_mod.PipelinePlanner = _SpyPlanner
            mgr.submit(scan_id)
            assert _wait(factory, scan_id) in ("completed", "failed")
            assert seen["discovered_hosts"] == ["app.example.com"]
            assert "unverified.example.com" not in seen["discovered_hosts"]
            with factory() as session:
                assert list(session.get(Scan, scan_id).target_snapshot or []) == scope
                assert list(session.get(Project, project_id).scope or []) == scope
        finally:
            ScanManager._run_discovery_pre_stage = orig_pre
            _mgr_mod.PipelinePlanner = orig_planner
            mgr.shutdown()

    def test_httpx_toolrun_contains_promoted_but_nmap_nuclei_do_not(self, tmp_path):
        from backend.services.discovery_service import DiscoveryResult

        factory = _factory(tmp_path)
        scope = [
            {"type": "domain", "value": "example.com"},
            {"type": "host", "value": "demo.local"},
        ]
        scan_id, _ = _seed(factory, scope=scope, profile="full")
        mgr = ScanManager(session_factory=factory, runs_dir=str(tmp_path / "runs"), resolver=lambda h: [])
        orig_pre = ScanManager._run_discovery_pre_stage

        def fake_pre(self, *, scan_id, registry, validator, cancel):
            return DiscoveryResult(
                parents=["example.com"],
                discovered=["app.example.com"],
                dns_verified=["app.example.com"],
                promoted=["app.example.com"],
            )

        try:
            ScanManager._run_discovery_pre_stage = fake_pre
            mgr.submit(scan_id)  # real PipelinePlanner path
            assert _wait(factory, scan_id) in ("completed", "failed")
            httpx = _tool_targets(factory, scan_id, "httpx")
            assert httpx and any("http://app.example.com" in t for t in httpx)
            for tool in ("nmap", "nuclei"):
                for targets in _tool_targets(factory, scan_id, tool):
                    assert not any("app.example.com" in str(t) for t in targets)
        finally:
            ScanManager._run_discovery_pre_stage = orig_pre
            mgr.shutdown()

    def test_original_untouched_narrow_runtime_gate(self, tmp_path):
        """Original Policy/validator unchanged; runtime validator is the
        narrow HTTPX-only gate (policy attr == original); runtime context
        policy carries promoted for the in-tool recheck."""
        from backend.services.discovery_service import DiscoveryResult
        import backend.services.scan_manager as _mgr_mod
        from agent_core.schemas.state import AgentState

        factory = _factory(tmp_path)
        scope = list(DOMAIN_SNAP)
        scan_id, _ = _seed(factory, scope=scope, profile="web")
        mgr = ScanManager(session_factory=factory, runs_dir=str(tmp_path / "runs"), resolver=lambda h: [])
        captured = {}
        orig_pre = ScanManager._run_discovery_pre_stage
        orig_runtime = _mgr_mod.AgentRuntime

        def fake_pre(self, *, scan_id, registry, validator, cancel):
            captured["original_allowed"] = list(validator.policy.allowed_targets)
            captured["original_policy_id"] = id(validator.policy)
            return DiscoveryResult(promoted=["app.example.com"])

        class _SpyRuntime(orig_runtime):
            def __init__(self, *, planner, registry, validator, store, events, policy):
                captured["runtime_ctx_allowed"] = list(policy.allowed_targets)
                captured["validator"] = validator
                captured["gate_policy_allowed"] = list(validator.policy.allowed_targets)
                super().__init__(
                    planner=planner, registry=registry, validator=validator,
                    store=store, events=events, policy=policy,
                )

        try:
            ScanManager._run_discovery_pre_stage = fake_pre
            _mgr_mod.AgentRuntime = _SpyRuntime
            mgr.submit(scan_id)
            assert _wait(factory, scan_id) in ("completed", "failed")
            assert captured["original_allowed"] == ["example.com"]
            # Gate exposes the ORIGINAL policy object (never a derived copy).
            assert captured["gate_policy_allowed"] == ["example.com"]
            assert id(captured["validator"].policy) == captured["original_policy_id"]
            # Context policy carries promoted so HTTPX in-tool recheck passes.
            assert "app.example.com" in captured["runtime_ctx_allowed"]
            # Narrow behavior through the ACTUAL runtime validator:
            st = AgentState(run_id="t", goal="g")
            gate = captured["validator"]
            assert gate.validate(
                ToolCall(tool="httpx", params={"targets": ["http://app.example.com"]}), st
            ).accepted
            assert not gate.validate(
                ToolCall(tool="nmap", params={"target": "app.example.com"}), st
            ).accepted
            assert not gate.validate(
                ToolCall(tool="nuclei", params={"targets": ["http://app.example.com"]}), st
            ).accepted
        finally:
            ScanManager._run_discovery_pre_stage = orig_pre
            _mgr_mod.AgentRuntime = orig_runtime
            mgr.shutdown()

    def test_empty_promoted_reuses_original(self, tmp_path):
        from backend.services.discovery_service import DiscoveryResult
        import backend.services.scan_manager as _mgr_mod

        factory = _factory(tmp_path)
        scope = [{"type": "host", "value": "demo.local"}]
        scan_id, _ = _seed(factory, scope=scope, profile="web")
        mgr = ScanManager(session_factory=factory, runs_dir=str(tmp_path / "runs"), resolver=lambda h: [])
        captured = {}
        orig_pre = ScanManager._run_discovery_pre_stage
        orig_runtime = _mgr_mod.AgentRuntime

        def fake_pre(self, *, scan_id, registry, validator, cancel):
            captured["original"] = list(validator.policy.allowed_targets)
            return DiscoveryResult()

        class _SpyRuntime(orig_runtime):
            def __init__(self, *, planner, registry, validator, store, events, policy):
                captured["runtime"] = list(policy.allowed_targets)
                super().__init__(
                    planner=planner, registry=registry, validator=validator,
                    store=store, events=events, policy=policy,
                )

        try:
            ScanManager._run_discovery_pre_stage = fake_pre
            _mgr_mod.AgentRuntime = _SpyRuntime
            mgr.submit(scan_id)
            assert _wait(factory, scan_id) in ("completed", "failed")
            assert captured["runtime"] == captured["original"]
        finally:
            ScanManager._run_discovery_pre_stage = orig_pre
            _mgr_mod.AgentRuntime = orig_runtime
            mgr.shutdown()

    def test_cancelled_discovery_never_uses_promoted(self, tmp_path):
        from backend.services.discovery_service import DiscoveryResult

        factory = _factory(tmp_path)
        scope = list(DOMAIN_SNAP)
        scan_id, _ = _seed(factory, scope=scope, profile="web")
        mgr = ScanManager(session_factory=factory, runs_dir=str(tmp_path / "runs"), resolver=lambda h: [])
        orig_pre = ScanManager._run_discovery_pre_stage
        from backend.services.scan_state import apply_transition

        def fake_pre(self, *, scan_id, registry, validator, cancel):
            with factory() as session:
                scan = session.get(Scan, scan_id)
                if scan.status == "running":
                    apply_transition(scan, "cancelling")
                    session.commit()
            cancel.set()
            return DiscoveryResult(status="cancelled", promoted=["app.example.com"])

        try:
            ScanManager._run_discovery_pre_stage = fake_pre
            mgr.submit(scan_id)
            assert _wait(factory, scan_id, want=("cancelled",)) == "cancelled"
            assert _tool_targets(factory, scan_id, "httpx") == []
        finally:
            ScanManager._run_discovery_pre_stage = orig_pre
            mgr.shutdown()
