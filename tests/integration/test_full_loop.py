"""Integration test: ScriptedPlanner -> MockPortScan -> MockWebProbe -> Finish.

Asserts the complete foundation behaves as one system: run finishes,
findings recorded, state persisted, trajectory written, expected events
emitted - all offline.
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


def _build(tmp_path):
    registry = ToolRegistry()
    registry.register(MockPortScan())
    registry.register(MockWebProbe())
    policy = Policy(allowed_targets=["demo.local"], max_danger="active_scan", max_steps=6)
    sink = InMemorySink()
    runtime = AgentRuntime(
        planner=ScriptedPlanner(ScriptedPlanner.demo_script("demo.local")),
        registry=registry,
        validator=SafetyValidator(registry, policy),
        store=JsonFileStore(tmp_path / "runs"),
        events=[sink],
        policy=policy,
    )
    return runtime, sink, tmp_path / "runs"


def test_full_mock_run(tmp_path):
    runtime, sink, runs_dir = _build(tmp_path)
    state = runtime.run("Recon demo.local")

    # 1. run finishes successfully
    assert state.status == "finished"
    assert state.step == 3

    # 2. findings exist and are well-formed
    assert len(state.findings) == 3  # 2 from port scan + 1 from web probe
    tools = {f.tool for f in state.findings}
    assert tools == {"mock_port_scan", "mock_web_probe"}
    assert all(f.id and f.title for f in state.findings)

    # 3. state was persisted
    state_path = runs_dir / state.run_id / "state.json"
    assert state_path.exists()
    persisted = json.loads(state_path.read_text(encoding="utf-8"))
    assert persisted["status"] == "finished"
    assert len(persisted["findings"]) == 3

    # 4. trajectory exists with one entry per step
    traj_path = runs_dir / state.run_id / "trajectory.jsonl"
    assert traj_path.exists()
    entries = [json.loads(l) for l in traj_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(entries) == 3
    assert entries[0]["decision_raw"]["tool"] == "mock_port_scan"
    assert entries[1]["decision_raw"]["tool"] == "mock_web_probe"
    assert entries[2]["decision_validated"]["kind"] == "finish"
    # reasoning is recorded for training but never in the executable view
    assert entries[0]["decision_raw"].get("reasoning")
    assert "reasoning" not in entries[0]["decision_validated"]

    # 5. expected events were emitted in order
    types = [e["type"] for e in sink.events]
    assert types[0] == "run.started"
    assert "step.started" in types
    assert "decision.proposed" in types
    assert "tool.started" in types
    assert "tool.finished" in types
    assert "finding.recorded" in types
    assert types[-1] == "run.finished"
    assert types.count("run.finished") == 1
    assert "run.failed" not in types


def test_rejected_decision_becomes_observation_and_loop_continues(tmp_path):
    registry = ToolRegistry()
    registry.register(MockPortScan())
    registry.register(MockWebProbe())
    policy = Policy(allowed_targets=["demo.local"], max_danger="active_scan", max_steps=8)
    sink = InMemorySink()
    planner = ScriptedPlanner(
        [
            # step 1: disallowed target -> rejected, must NOT execute
            ToolCall(tool="mock_port_scan", params={"target": "forbidden.local"}),
            # step 2: allowed call
            ToolCall(tool="mock_port_scan", params={"target": "demo.local"}),
            # step 3: finish
            Finish(summary="ok"),
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
    state = runtime.run("g")

    assert state.status == "finished"
    # step 1 produced a rejection observation, not a tool result
    assert state.observations[0].source == "rejected"
    assert "not in the allowed targets" in state.observations[0].reason
    # step 2 executed normally
    assert state.observations[1].source == "tool"
    assert state.findings  # only from the allowed call

    types = [e["type"] for e in sink.events]
    assert "decision.rejected" in types
    # exactly one execution for the port scan
    assert types.count("tool.started") == 1

    # trajectory records the rejection with its reason
    traj = JsonFileStore(tmp_path / "runs").read_trajectory(state.run_id)
    assert traj[0]["rejected"] is True
    assert "not in the allowed targets" in traj[0]["rejection_reason"]


def test_findings_persisted_in_state(tmp_path):
    runtime, _, runs_dir = _build(tmp_path)
    state = runtime.run("g")
    loaded = JsonFileStore(runs_dir).load_state(state.run_id)
    assert loaded is not None
    assert len(loaded.findings) == 3
    assert loaded.status == "finished"
