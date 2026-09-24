"""Stage 1 (M3-C): REAL OpenAICompatibleProvider + ModelPlanner + MOCK tools.

The HTTP transport is stubbed at urlopen (offline, no credentials), so
these tests exercise the genuine provider class end to end:

    stubbed chat endpoint -> OpenAICompatibleProvider -> ModelPlanner
    -> SafetyValidator -> mock tool -> Observation -> trajectory

This proves the nine required behaviors without any external API.
"""
from __future__ import annotations

import io
import json

from agent_core.planner import ModelPlanner
from agent_core.providers.openai_compatible import OpenAICompatibleProvider
from agent_core.runtime import AgentRuntime, InMemorySink
from agent_core.safety.policy import Policy
from agent_core.safety.validator import SafetyValidator
from agent_core.state import JsonFileStore
from agent_core.tools.mocks import MockPortScan, MockWebProbe
from agent_core.tools.registry import ToolRegistry


class _FakeHTTPResponse:
    def __init__(self, payload: bytes):
        self._buf = io.BytesIO(payload)

    def read(self):
        return self._buf.read()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _stub_endpoint(monkeypatch, responses):
    """Queue raw completion strings behind the provider's HTTP call."""
    calls = {"n": 0}

    def fake_urlopen(req, timeout=None):
        body = responses[min(calls["n"], len(responses) - 1)]
        calls["n"] += 1
        payload = json.dumps({"choices": [{"message": {"content": body}}]}).encode()
        return _FakeHTTPResponse(payload)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    return calls


def _runtime(tmp_path, monkeypatch, responses, max_steps=6, targets=("demo.local",)):
    _stub_endpoint(monkeypatch, responses)
    registry = ToolRegistry()
    registry.register(MockPortScan())
    registry.register(MockWebProbe())
    policy = Policy(allowed_targets=list(targets), max_danger="active_scan", max_steps=max_steps)
    sink = InMemorySink()
    provider = OpenAICompatibleProvider("http://localhost:1/v1", "", "test-model")
    planner = ModelPlanner(provider, registry, allowed_targets=list(targets))
    runtime = AgentRuntime(
        planner=planner,
        registry=registry,
        validator=SafetyValidator(registry, policy),
        store=JsonFileStore(tmp_path / "runs"),
        events=[sink],
        policy=policy,
    )
    return runtime, sink


TOOLCALL = (
    '{"kind": "tool_call", "tool": "mock_port_scan", '
    '"params": {"target": "demo.local"}, "reasoning": "map ports."}'
)
FINISH = '{"kind": "finish", "summary": "Recon complete."}'


def test_valid_decision_reaches_validator_and_executes(tmp_path, monkeypatch):
    runtime, sink = _runtime(tmp_path, monkeypatch, [TOOLCALL, FINISH])
    state = runtime.run("Recon demo.local")
    assert state.status == "finished" and state.step == 2
    assert state.observations[0].source == "tool"
    assert state.observations[0].tool == "mock_port_scan"
    assert "tool.finished" in [e["type"] for e in sink.events]


def test_unknown_tool_rejected_downstream(tmp_path, monkeypatch):
    runtime, _ = _runtime(
        tmp_path, monkeypatch,
        ['{"kind": "tool_call", "tool": "shell", "params": {}}', FINISH],
    )
    state = runtime.run("g")
    assert state.status == "finished"
    assert state.observations[0].source == "rejected"
    assert "unknown tool" in state.observations[0].reason


def test_malformed_decision_fails_safely(tmp_path, monkeypatch):
    runtime, sink = _runtime(tmp_path, monkeypatch, ["definitely not json"])
    state = runtime.run("g")
    assert state.status == "failed"
    assert "tool.started" not in [e["type"] for e in sink.events]
    assert state.observations == []


def test_invalid_params_rejected(tmp_path, monkeypatch):
    runtime, _ = _runtime(
        tmp_path, monkeypatch,
        ['{"kind": "tool_call", "tool": "mock_port_scan", "params": {"ports": "all"}}', FINISH],
    )
    state = runtime.run("g")
    assert state.observations[0].source == "rejected"
    assert "invalid parameters" in state.observations[0].reason


def test_unauthorized_target_rejected(tmp_path, monkeypatch):
    runtime, _ = _runtime(
        tmp_path, monkeypatch,
        ['{"kind": "tool_call", "tool": "mock_port_scan", "params": {"target": "evil.example"}}', FINISH],
    )
    state = runtime.run("g")
    assert state.observations[0].source == "rejected"
    assert "allowed targets" in state.observations[0].reason
    assert state.findings == []


def test_finish_only_executes_nothing(tmp_path, monkeypatch):
    runtime, sink = _runtime(tmp_path, monkeypatch, [FINISH])
    state = runtime.run("g")
    assert state.status == "finished" and state.step == 1
    assert "tool.started" not in [e["type"] for e in sink.events]


def test_max_steps_enforced(tmp_path, monkeypatch):
    runtime, _ = _runtime(tmp_path, monkeypatch, [TOOLCALL] * 10, max_steps=3)
    state = runtime.run("g")
    assert state.status == "failed" and "max_steps" in state.error
    assert state.step == 3


def test_trajectory_records_proposed_and_validated(tmp_path, monkeypatch):
    runtime, _ = _runtime(tmp_path, monkeypatch, [TOOLCALL, FINISH])
    state = runtime.run("g")
    traj = JsonFileStore(tmp_path / "runs").read_trajectory(state.run_id)
    assert len(traj) == 2
    assert traj[0]["decision_raw"]["tool"] == "mock_port_scan"
    assert traj[0]["decision_raw"]["reasoning"] == "map ports."
    assert "reasoning" not in traj[0]["decision_validated"]
    assert traj[1]["decision_validated"]["kind"] == "finish"


def test_provider_error_fails_safely(tmp_path, monkeypatch):
    import urllib.error

    def dead(req, timeout=None):
        raise urllib.error.URLError("refused")

    monkeypatch.setattr("urllib.request.urlopen", dead)
    registry = ToolRegistry()
    registry.register(MockPortScan())
    policy = Policy(allowed_targets=["demo.local"], max_steps=6)
    runtime = AgentRuntime(
        planner=ModelPlanner(
            OpenAICompatibleProvider("http://localhost:1/v1", "", "m"),
            registry,
            allowed_targets=["demo.local"],
        ),
        registry=registry,
        validator=SafetyValidator(registry, policy),
        store=JsonFileStore(tmp_path / "runs"),
        events=[InMemorySink()],
        policy=policy,
    )
    state = runtime.run("g")
    assert state.status == "failed"
    assert state.observations == []  # nothing proposed, nothing executed
