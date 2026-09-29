"""Integration: ScriptedPlanner -> SubfinderTool (mocked) -> Observation -> Finish.

Proves the full MODEL PROPOSES -> VALIDATOR AUTHORIZES -> TOOL EXECUTES
path for passive discovery: the proposed domain is allowlisted, the
runner output becomes a normalized observation, and discovered names
stay DATA (no scope/allowlist mutation is possible from here).
"""
from __future__ import annotations

import json

from agent_core.planner import ScriptedPlanner
from agent_core.runtime import AgentRuntime, InMemorySink
from agent_core.safety.policy import Policy
from agent_core.safety.validator import SafetyValidator
from agent_core.schemas.actions import Finish, ToolCall
from agent_core.state import JsonFileStore
from agent_core.tools.mocks import MockPortScan, MockWebProbe
from agent_core.tools.registry import ToolRegistry
from agent_core.tools.subfinder import SubfinderTool
from agent_core.tools.subprocess import SubprocessResult

LINES = "\n".join(
    [
        json.dumps({"host": "api.demo.local", "input": "demo.local", "source": "crtsh"}),
        json.dumps({"host": "dev.demo.local", "input": "demo.local", "source": "github"}),
    ]
)


def _resolver(hostname: str) -> list[str]:
    return ["10.0.0.9"] if hostname == "api.demo.local" else []


def test_subfinder_loop_with_full_registry(tmp_path):
    registry = ToolRegistry()
    registry.register(MockPortScan())
    registry.register(MockWebProbe())
    registry.register(
        SubfinderTool(
            runner=lambda *a, **k: SubprocessResult(stdout=LINES, stderr="", returncode=0),
            resolver=_resolver,
        )
    )
    assert registry.names() == ["mock_port_scan", "mock_web_probe", "subfinder"]

    policy = Policy(allowed_targets=["demo.local"], max_danger="active_scan", max_steps=6)
    sink = InMemorySink()
    planner = ScriptedPlanner(
        [
            ToolCall(tool="subfinder", params={"domain": "demo.local"}),
            Finish(summary="discovery done"),
        ]
    )
    runtime = AgentRuntime(
        planner=planner,
        registry=registry,
        validator=SafetyValidator(registry, policy),
        store=JsonFileStore(tmp_path / "runs"),
        events=[sink],
        policy=policy,
    )
    state = runtime.run("Discover subdomains of demo.local")
    assert state.status == "finished" and state.step == 2
    assert state.observations[0].source == "tool"
    assert state.observations[0].tool == "subfinder"
    data = state.observations[0].data
    assert data["domain"] == "demo.local"
    by_host = {s["host"]: s for s in data["subdomains"]}
    assert by_host["api.demo.local"]["verification_status"] == "resolved"
    assert by_host["api.demo.local"]["dns_a"] == ["10.0.0.9"]
    assert by_host["dev.demo.local"]["verification_status"] == "unverified"
    assert state.findings == []
    # allowlist unchanged by discovery: the validator still rejects the
    # discovered name for active tools.
    v = SafetyValidator(registry, policy)
    from agent_core.schemas.state import AgentState

    out = v.validate(
        ToolCall(tool="mock_port_scan", params={"target": "api.demo.local"}),
        AgentState(run_id="x", goal="g"),
    )
    assert not out.accepted
    traj = JsonFileStore(tmp_path / "runs").read_trajectory(state.run_id)
    assert len(traj) == 2
