"""Unit tests: ModelPlanner strict parsing + bounded requests (mock only)."""
from __future__ import annotations

import json

import pytest

from agent_core.planner.base import Planner
from agent_core.planner.model import (
    MAX_DATA_CHARS,
    MAX_GOAL_CHARS,
    MAX_OBSERVATIONS,
    ModelPlanner,
    ModelPlannerError,
    build_model_request,
)
from agent_core.providers.mock import MockModelProvider
from agent_core.safety.policy import Policy
from agent_core.safety.validator import SafetyValidator
from agent_core.schemas.actions import Finish, ToolCall
from agent_core.schemas.results import Observation
from agent_core.schemas.state import AgentState
from agent_core.tools.mocks import MockPortScan, MockWebProbe
from agent_core.tools.registry import ToolRegistry


def _registry():
    reg = ToolRegistry()
    reg.register(MockPortScan())
    reg.register(MockWebProbe())
    return reg


def _state(goal="Recon demo.local", observations=None):
    return AgentState(
        run_id="t", goal=goal, max_steps=6, observations=list(observations or [])
    )


def _obs(summary="probed", tool="mock_web_probe", data=None):
    return Observation(
        step=1, source="tool", tool=tool, ok=True, summary=summary,
        data=data or {}, findings=[],
    )


def test_satisfies_planner_protocol():
    assert isinstance(ModelPlanner(MockModelProvider(), _registry()), Planner)


def test_valid_toolcall_response():
    planner = ModelPlanner(
        MockModelProvider(['{"kind": "tool_call", "tool": "mock_web_probe", '
                           '"params": {"url": "http://demo.local"}, '
                           '"reasoning": "probe the web surface."}']),
        _registry(),
    )
    decision = planner.decide(_state())
    assert isinstance(decision, ToolCall)
    assert decision.tool == "mock_web_probe"
    assert decision.params == {"url": "http://demo.local"}


def test_valid_finish_response():
    planner = ModelPlanner(
        MockModelProvider(['{"kind": "finish", "summary": "Recon done."}']),
        _registry(),
    )
    decision = planner.decide(_state())
    assert isinstance(decision, Finish)
    assert decision.summary == "Recon done."


def test_malformed_json_fails_cleanly():
    planner = ModelPlanner(MockModelProvider(["this is not json"]), _registry())
    with pytest.raises(ModelPlannerError):
        planner.decide(_state())


def test_invalid_schema_rejected():
    planner = ModelPlanner(
        MockModelProvider(['{"kind": "tool_call"}']), _registry()  # missing tool
    )
    with pytest.raises(ModelPlannerError):
        planner.decide(_state())


def test_extra_fields_rejected_by_strict_schema():
    planner = ModelPlanner(
        MockModelProvider(['{"kind": "finish", "summary": "done", "hacker": true}']),
        _registry(),
    )
    with pytest.raises(ModelPlannerError):
        planner.decide(_state())


def test_unknown_tool_parses_but_never_executes():
    """Planner is schema-only: it proposes, it never executes or authorizes."""
    calls: list = []
    provider = MockModelProvider(
        ['{"kind": "tool_call", "tool": "shell", "params": {"cmd": "rm -rf /"}}']
    )
    orig = provider.generate
    provider.generate = lambda req: (calls.append(req), orig(req))[1]
    planner = ModelPlanner(provider, _registry())
    decision = planner.decide(_state())
    assert isinstance(decision, ToolCall) and decision.tool == "shell"
    assert len(calls) == 1  # exactly one provider call, zero tool executions


def test_provider_failure_is_controlled():
    class Boom:
        def generate(self, request):
            raise ConnectionError("endpoint down")

    with pytest.raises(ModelPlannerError, match="provider failed"):
        ModelPlanner(Boom(), _registry()).decide(_state())


def test_request_is_bounded_and_scoped():
    big_data = {"blob": "x" * (MAX_DATA_CHARS + 5000), "raw_xml": "<nmaprun>" + "y" * 5000}
    observations = [_obs(summary=f"obs {i} " + "s" * 600, data=dict(big_data)) for i in range(10)]
    state = _state(goal="G" * (MAX_GOAL_CHARS + 100), observations=observations)
    req = build_model_request(state, _registry(), allowed_targets=["demo.local"])
    assert req.response_format == "json"
    assert req.messages[0].role == "system"
    user = json.loads(req.messages[1].content)
    assert len(user["goal"]) <= MAX_GOAL_CHARS + len("...[truncated]")
    assert len(user["recent_observations"]) == MAX_OBSERVATIONS
    assert len(user["recent_observations"][0]["summary"]) <= 500 + len("...[truncated]")
    assert len(user["recent_observations"][0]["data"]) <= MAX_DATA_CHARS + len("...[truncated]")
    assert user["scope"] == {"allowed_targets": ["demo.local"]}
    assert {t["name"] for t in req.tool_schemas} == {"mock_port_scan", "mock_web_probe"}
    assert all("danger_level" in t and "input_schema" in t for t in req.tool_schemas)
    # tool schemas expose metadata only - no binaries, no shell syntax
    dumped = json.dumps(req.tool_schemas)
    assert "shell=True" not in dumped and "/bin/" not in dumped


def test_model_output_is_not_authorization():
    """Malicious model output parses but MUST die at SafetyValidator."""
    planner = ModelPlanner(
        MockModelProvider(['{"kind": "tool_call", "tool": "nuclei", '
                           '"params": {"targets": ["evil.example"]}}']),
        _registry(),
    )
    decision = planner.decide(_state())
    assert isinstance(decision, ToolCall)  # parsing succeeds...

    from agent_core.tools.nuclei import NucleiTool

    reg = ToolRegistry()
    reg.register(NucleiTool())
    policy = Policy(allowed_targets=["demo.local"], max_danger="active_scan", max_steps=6)
    outcome = SafetyValidator(reg, policy).validate(decision, _state())
    assert not outcome.accepted  # ...but authorization fails
    assert "allowed targets" in outcome.reason
