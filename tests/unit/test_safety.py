"""Unit tests: SafetyValidator two-stage validation + Policy rules."""
from __future__ import annotations

import pytest

from agent_core.planner import ScriptedPlanner
from agent_core.runtime import AgentRuntime, InMemorySink
from agent_core.safety.policy import Policy
from agent_core.safety.validator import SafetyValidator
from agent_core.schemas.actions import Finish, ToolCall
from agent_core.schemas.state import AgentState
from agent_core.tools.mocks import MockPortScan, MockWebProbe
from agent_core.tools.registry import ToolRegistry
from agent_core.state.store import JsonFileStore


def _state(tmp_path, max_steps=6):
    return AgentState(run_id="t", goal="g", max_steps=max_steps)


def _validator(max_danger="active_scan", targets=("demo.local",)):
    reg = ToolRegistry()
    reg.register(MockPortScan())
    reg.register(MockWebProbe())
    policy = Policy(
        allowed_targets=list(targets), max_danger=max_danger, max_steps=6
    )
    return SafetyValidator(reg, policy)


class TestStage1Schema:
    def test_unknown_tool_rejected(self):
        v = _validator()
        state = _state(None)
        out = v.validate(ToolCall(tool="nmap", params={}), state)
        assert not out.accepted
        assert "unknown tool" in out.reason

    def test_invalid_params_rejected(self):
        v = _validator()
        state = _state(None)
        out = v.validate(ToolCall(tool="mock_port_scan", params={"ports": "all"}), state)
        assert not out.accepted
        assert "invalid parameters" in out.reason

    def test_missing_required_param_rejected(self):
        v = _validator()
        state = _state(None)
        out = v.validate(ToolCall(tool="mock_port_scan", params={}), state)
        assert not out.accepted

    def test_valid_call_accepted(self):
        v = _validator()
        state = _state(None)
        out = v.validate(
            ToolCall(tool="mock_port_scan", params={"target": "demo.local"}), state
        )
        assert out.accepted
        assert out.tool.name == "mock_port_scan"
        # validated_params is the tool's Pydantic model
        assert out.validated_params.target == "demo.local"


class TestStage2Policy:
    def test_target_allowlist_rejection(self):
        v = _validator(targets=("demo.local",))
        out = v.validate(
            ToolCall(tool="mock_port_scan", params={"target": "evil.example.com"}),
            _state(None),
        )
        assert not out.accepted
        assert "not in the allowed targets" in out.reason

    def test_url_target_normalized_to_host(self):
        v = _validator(targets=("demo.local",))
        out = v.validate(
            ToolCall(tool="mock_web_probe", params={"url": "http://demo.local:8080/x"}),
            _state(None),
        )
        assert out.accepted

    def test_url_to_other_host_rejected(self):
        v = _validator(targets=("demo.local",))
        out = v.validate(
            ToolCall(tool="mock_web_probe", params={"url": "http://other.local"}),
            _state(None),
        )
        assert not out.accepted

    def test_danger_level_rejection(self):
        v = _validator(max_danger="safe")
        out = v.validate(
            ToolCall(tool="mock_port_scan", params={"target": "demo.local"}),
            _state(None),
        )
        assert not out.accepted
        assert "danger level" in out.reason

    def test_safe_tool_passes_safe_cap(self):
        v = _validator(max_danger="safe")
        out = v.validate(
            ToolCall(tool="mock_web_probe", params={"url": "http://demo.local"}),
            _state(None),
        )
        assert out.accepted

    def test_finish_always_accepted(self):
        v = _validator()
        out = v.validate(Finish(summary="done"), _state(None))
        assert out.accepted


class TestMaxSteps:
    def _runtime(self, tmp_path, max_steps):
        reg = ToolRegistry()
        reg.register(MockPortScan())
        policy = Policy(allowed_targets=["demo.local"], max_steps=max_steps)
        # Script never finishes -> forces max-step stop
        script = ScriptedPlanner(
            [ToolCall(tool="mock_port_scan", params={"target": "demo.local"})] * (max_steps + 2)
        )
        return AgentRuntime(
            planner=script,
            registry=reg,
            validator=SafetyValidator(reg, policy),
            store=JsonFileStore(tmp_path / "runs"),
            events=[InMemorySink()],
            policy=policy,
        )

    def test_runtime_stops_at_max_steps(self, tmp_path):
        rt = self._runtime(tmp_path, max_steps=3)
        state = rt.run("g")
        assert state.status == "failed"
        assert "max_steps" in state.error
        assert state.step == 3
