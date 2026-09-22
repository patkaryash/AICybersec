"""Contract tests: any ModelProvider / Tool / Planner implementation must
pass these.  This is what makes "the model is replaceable" a tested
property instead of a hope.

When the team adds a real provider or a real security tool, import it
here and add it to the factory lists - if it breaks the contract, these
tests fail before the runtime ever sees it.
"""
from __future__ import annotations

import pytest
from pydantic import BaseModel

from agent_core.planner.base import Planner
from agent_core.providers.base import (
    Message,
    ModelProvider,
    ModelRequest,
    ModelResponse,
)
from agent_core.providers.mock import MockModelProvider
from agent_core.runtime.events import EventSink, InMemorySink
from agent_core.schemas.results import ToolResult
from agent_core.tools.base import Tool, ToolContext
from agent_core.tools.mocks import MockPortScan, MockWebProbe
from agent_core.tools.registry import ToolRegistry

PROVIDER_FACTORIES = [MockModelProvider]
TOOL_FACTORIES = [MockPortScan, MockWebProbe]


class TestProviderContract:
    @pytest.mark.parametrize("factory", PROVIDER_FACTORIES)
    def test_satisfies_protocol(self, factory):
        provider = factory()
        assert isinstance(provider, ModelProvider)

    @pytest.mark.parametrize("factory", PROVIDER_FACTORIES)
    def test_returns_raw_text_only(self, factory):
        provider = factory()
        request = ModelRequest(
            messages=[Message(role="user", content="hello")],
            tool_schemas=[],
            response_format="json",
        )
        response = provider.generate(request)
        assert isinstance(response, ModelResponse)
        assert isinstance(response.raw_text, str)


class TestToolContract:
    @pytest.mark.parametrize("factory", TOOL_FACTORIES)
    def test_satisfies_interface(self, factory):
        tool = factory()
        assert isinstance(tool, Tool)
        assert isinstance(tool.name, str) and tool.name
        assert isinstance(tool.description, str) and tool.description
        assert issubclass(tool.input_model, BaseModel)
        assert tool.danger_level in ("safe", "active_scan", "intrusive")

    @pytest.mark.parametrize("factory", TOOL_FACTORIES)
    def test_spec_is_model_facing(self, factory):
        spec = factory().spec()
        assert spec.name == factory.name
        assert spec.input_schema.get("type") == "object"
        assert spec.danger_level == factory.danger_level

    @pytest.mark.parametrize("factory", TOOL_FACTORIES)
    def test_execute_is_deterministic(self, factory):
        """Mock tools must be deterministic: same input -> same output."""
        tool = factory()
        ctx = ToolContext(run_id="t", allowed_targets=["demo.local"])
        if tool.name == "mock_port_scan":
            params = tool.validate_params({"target": "demo.local"})
        else:
            params = tool.validate_params({"url": "http://demo.local"})
        r1 = tool.execute(params, ctx)
        r2 = tool.execute(params, ctx)
        assert r1 == r2
        assert isinstance(r1, ToolResult)
        assert r1.status in ("ok", "error", "timeout")
        assert r1.summary  # summary always present for the model
        for f in r1.findings:
            assert f.tool == tool.name
            assert f.id.startswith(tool.name)


class TestPlannerContract:
    def test_scripted_planner_satisfies_protocol(self):
        from agent_core.planner.scripted import ScriptedPlanner

        planner = ScriptedPlanner(ScriptedPlanner.demo_script("demo.local"))
        assert isinstance(planner, Planner)

    def test_sink_satisfies_protocol(self):
        assert isinstance(InMemorySink(), EventSink)


class TestRegistryIsWhitelist:
    def test_model_cannot_reach_unregistered_tools(self):
        reg = ToolRegistry()
        for factory in TOOL_FACTORIES:
            reg.register(factory())
        assert set(reg.names()) == {f.name for f in TOOL_FACTORIES}
        with pytest.raises(KeyError):
            reg.get("shell")
