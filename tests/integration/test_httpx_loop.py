"""Integration: ScriptedPlanner -> HTTPXTool (mocked) -> Observation -> Finish."""
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
from agent_core.tools.registry import ToolRegistry
from agent_core.tools.subprocess import SubprocessResult

LINE = json.dumps({
    "url": "https://demo.local/login", "input": "https://demo.local",
    "status_code": 200, "title": "Login", "tech": ["nginx"],
})


def test_httpx_loop_with_full_registry(tmp_path):
    registry = ToolRegistry()
    registry.register(MockPortScan())
    registry.register(MockWebProbe())
    registry.register(NmapTool())
    registry.register(
        HTTPXTool(runner=lambda *a, **k: SubprocessResult(stdout=LINE, stderr="", returncode=0))
    )
    assert registry.names() == ["httpx", "mock_port_scan", "mock_web_probe", "nmap"]

    policy = Policy(allowed_targets=["demo.local"], max_danger="active_scan", max_steps=6)
    sink = InMemorySink()
    planner = ScriptedPlanner(
        [
            ToolCall(tool="httpx", params={"targets": ["https://demo.local"]}),
            Finish(summary="http recon done"),
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
    state = runtime.run("Probe demo.local HTTP")
    assert state.status == "finished" and state.step == 2
    assert state.observations[0].source == "tool"
    assert state.observations[0].tool == "httpx"
    assert "Login" in state.observations[0].summary
    assert state.observations[0].data["services"][0]["status_code"] == 200
    traj = JsonFileStore(tmp_path / "runs").read_trajectory(state.run_id)
    assert len(traj) == 2
