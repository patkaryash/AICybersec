"""Integration: ScriptedPlanner -> NmapTool (mocked) -> Observation -> Finish."""
from __future__ import annotations

from agent_core.planner import ScriptedPlanner
from agent_core.runtime import AgentRuntime, InMemorySink
from agent_core.safety.policy import Policy
from agent_core.safety.validator import SafetyValidator
from agent_core.schemas.actions import Finish, ToolCall
from agent_core.state import JsonFileStore
from agent_core.tools.mocks import MockPortScan, MockWebProbe
from agent_core.tools.nmap import NmapTool
from agent_core.tools.registry import ToolRegistry
from agent_core.tools.subprocess import SubprocessResult

XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap"><host><status state="up" reason="syn-ack"/>
<address addr="demo.local" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
<service name="http" product="nginx" version="1.24" method="probed" conf="10"/></port>
</ports></host></nmaprun>"""


def test_nmap_loop_with_mocks_intact(tmp_path):
    registry = ToolRegistry()
    registry.register(MockPortScan())
    registry.register(MockWebProbe())
    registry.register(
        NmapTool(runner=lambda *a, **k: SubprocessResult(stdout=XML, stderr="", returncode=0))
    )
    assert registry.names() == ["mock_port_scan", "mock_web_probe", "nmap"]

    policy = Policy(allowed_targets=["demo.local"], max_danger="active_scan", max_steps=6)
    sink = InMemorySink()
    planner = ScriptedPlanner(
        [
            ToolCall(tool="nmap", params={"target": "demo.local"}),
            Finish(summary="recon done"),
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
    state = runtime.run("Recon demo.local with nmap")
    assert state.status == "finished"
    assert state.step == 2
    assert state.observations[0].source == "tool"
    assert state.observations[0].tool == "nmap"
    assert "is up" in state.observations[0].summary
    assert state.observations[0].data["hosts"][0]["ports"][0]["port"] == 80
    # trajectory bounded: no raw XML blob
    traj = JsonFileStore(tmp_path / "runs").read_trajectory(state.run_id)
    assert len(traj) == 2
    assert "<nmaprun" not in str(traj[0])
