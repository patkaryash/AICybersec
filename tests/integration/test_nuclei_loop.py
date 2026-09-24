"""Integration: ScriptedPlanner -> NucleiTool (mocked) -> Observation -> Finish."""
from __future__ import annotations

import json

from agent_core.planner import ScriptedPlanner
from agent_core.runtime import AgentRuntime, InMemorySink
from agent_core.safety.policy import Policy
from agent_core.safety.validator import SafetyValidator
from agent_core.schemas.actions import Finish, ToolCall
from agent_core.state import JsonFileStore
from agent_core.tools.httpx import HTTPXTool
from agent_core.tools.mocks import MockPortScan, MockWebProbe
from agent_core.tools.nmap import NmapTool
from agent_core.tools.nuclei import NucleiTool
from agent_core.tools.registry import ToolRegistry
from agent_core.tools.subprocess import SubprocessResult

LINE = json.dumps({
    "template-id": "CVE-2021-44228",
    "info": {"name": "Apache Log4j RCE", "severity": "critical"},
    "matched-at": "https://demo.local/login",
    "host": "https://demo.local",
})


def test_nuclei_loop_with_full_registry(tmp_path):
    registry = ToolRegistry()
    registry.register(MockPortScan())
    registry.register(MockWebProbe())
    registry.register(NmapTool())
    registry.register(HTTPXTool())
    registry.register(
        NucleiTool(runner=lambda *a, **k: SubprocessResult(stdout=LINE, stderr="", returncode=0))
    )
    assert registry.names() == ["httpx", "mock_port_scan", "mock_web_probe", "nmap", "nuclei"]

    policy = Policy(allowed_targets=["demo.local"], max_danger="active_scan", max_steps=6)
    sink = InMemorySink()
    planner = ScriptedPlanner(
        [
            ToolCall(tool="nuclei", params={"targets": ["https://demo.local"]}),
            Finish(summary="vuln scan done"),
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
    state = runtime.run("Scan demo.local for known vulns")
    assert state.status == "finished" and state.step == 2
    assert state.observations[0].source == "tool"
    assert state.observations[0].tool == "nuclei"
    assert len(state.findings) == 1
    assert state.findings[0].tool == "nuclei"
    assert state.findings[0].severity == "critical"
    assert "1 finding" in state.observations[0].summary
    traj = JsonFileStore(tmp_path / "runs").read_trajectory(state.run_id)
    assert len(traj) == 2
    assert "template-id" not in str(traj[0])  # normalized only, no raw dump
