"""Integration: ModelPlanner -> SafetyValidator -> real tool -> Finish.

Uses MockModelProvider (queued JSON) and a mocked httpx runner: no LLM,
no network, no binaries. Proves the runtime consumes ModelPlanner through
the unchanged Planner interface, including rejection of a disallowed
target and the Finish-only path.
"""
from __future__ import annotations

import json

from agent_core.planner import ModelPlanner
from agent_core.providers.mock import MockModelProvider
from agent_core.runtime import AgentRuntime, InMemorySink
from agent_core.safety.policy import Policy
from agent_core.safety.validator import SafetyValidator
from agent_core.state import JsonFileStore
from agent_core.tools.httpx import HTTPXTool
from agent_core.tools.registry import ToolRegistry
from agent_core.tools.subprocess import SubprocessResult

LINE = json.dumps({
    "url": "https://demo.local/login", "input": "https://demo.local",
    "status_code": 200, "title": "Login", "tech": ["nginx"],
})


def _runtime(tmp_path, responses):
    registry = ToolRegistry()
    registry.register(
        HTTPXTool(runner=lambda *a, **k: SubprocessResult(stdout=LINE, stderr="", returncode=0))
    )
    policy = Policy(allowed_targets=["demo.local"], max_danger="safe", max_steps=6)
    sink = InMemorySink()
    planner = ModelPlanner(
        MockModelProvider(list(responses)), registry, allowed_targets=["demo.local"]
    )
    runtime = AgentRuntime(
        planner=planner,
        registry=registry,
        validator=SafetyValidator(registry, policy),
        store=JsonFileStore(tmp_path / "runs"),
        events=[sink],
        policy=policy,
    )
    return runtime, sink


def test_model_driven_httpx_then_finish(tmp_path):
    runtime, sink = _runtime(tmp_path, [
        '{"kind": "tool_call", "tool": "httpx", "params": {"targets": ["https://demo.local"]}, '
        '"reasoning": "Enumerate HTTP services first."}',
        '{"kind": "finish", "summary": "HTTP recon complete."}',
    ])
    state = runtime.run("Probe demo.local HTTP")
    assert state.status == "finished" and state.step == 2
    assert state.observations[0].source == "tool"
    assert state.observations[0].tool == "httpx"
    assert "Login" in state.observations[0].summary
    types = [e["type"] for e in sink.events]
    assert "decision.proposed" in types and "tool.finished" in types
    assert types[-1] == "run.finished"
    traj = JsonFileStore(tmp_path / "runs").read_trajectory(state.run_id)
    assert len(traj) == 2
    assert traj[0]["decision_raw"]["tool"] == "httpx"


def test_model_driven_disallowed_target_rejected(tmp_path):
    runtime, _ = _runtime(tmp_path, [
        '{"kind": "tool_call", "tool": "httpx", "params": {"targets": ["https://evil.example"]}}',
        '{"kind": "finish", "summary": "Nothing authorized to do."}',
    ])
    state = runtime.run("Probe evil")
    assert state.status == "finished"
    assert state.observations[0].source == "rejected"
    assert "allowed targets" in state.observations[0].reason


def test_model_driven_finish_only_executes_nothing(tmp_path):
    runtime, sink = _runtime(tmp_path, [
        '{"kind": "finish", "summary": "Nothing to do."}',
    ])
    state = runtime.run("No-op")
    assert state.status == "finished" and state.step == 1
    assert state.observations == []
    assert "tool.started" not in [e["type"] for e in sink.events]
