"""Unit tests: DangerLevel, ToolSpec, ToolRegistry, ToolContext."""
from __future__ import annotations

import pytest
from pydantic import BaseModel

from agent_core.schemas.results import ToolResult
from agent_core.schemas.tools import DangerLevel, ToolSpec
from agent_core.tools.base import Tool, ToolContext
from agent_core.tools.registry import ToolRegistry


class _Params(BaseModel):
    target: str


class _DummyTool(Tool):
    name = "dummy"
    description = "dummy tool"
    input_model = _Params
    danger_level = "safe"

    def execute(self, params, ctx):
        return ToolResult(status="ok", summary="ok")


class TestDangerLevel:
    def test_ordering(self):
        assert not DangerLevel.exceeds("safe", "active_scan")
        assert not DangerLevel.exceeds("active_scan", "active_scan")
        assert DangerLevel.exceeds("intrusive", "active_scan")
        assert DangerLevel.exceeds("active_scan", "safe")

    def test_unknown_level(self):
        with pytest.raises(KeyError):
            DangerLevel.rank("nuclear")


class TestToolSpec:
    def test_spec_contains_contract_fields(self):
        spec = _DummyTool().spec()
        assert isinstance(spec, ToolSpec)
        assert spec.name == "dummy"
        assert spec.description == "dummy tool"
        assert spec.danger_level == "safe"
        assert spec.input_schema["type"] == "object"
        assert "target" in spec.input_schema["properties"]

    def test_spec_rejects_bad_name(self):
        with pytest.raises(Exception):
            ToolSpec(name="Bad Name", description="x", input_schema={}, danger_level="safe")


class TestToolRegistry:
    def test_register_and_get(self):
        reg = ToolRegistry()
        tool = _DummyTool()
        reg.register(tool)
        assert reg.get("dummy") is tool
        assert reg.has("dummy")
        assert reg.names() == ["dummy"]

    def test_unknown_tool_raises_keyerror(self):
        reg = ToolRegistry()
        with pytest.raises(KeyError):
            reg.get("nope")

    def test_duplicate_registration_rejected(self):
        reg = ToolRegistry()
        reg.register(_DummyTool())
        with pytest.raises(ValueError, match="already registered"):
            reg.register(_DummyTool())

    def test_schemas_lists_all_tools(self):
        reg = ToolRegistry()
        reg.register(_DummyTool())
        specs = reg.schemas()
        assert len(specs) == 1
        assert specs[0].name == "dummy"

    def test_registry_is_a_whitelist(self):
        # nothing registered -> nothing executable
        reg = ToolRegistry()
        assert reg.list() == []
        with pytest.raises(KeyError):
            reg.get("mock_port_scan")


class TestToolContext:
    def test_defaults(self):
        ctx = ToolContext(run_id="r1", allowed_targets=["demo.local"])
        assert ctx.timeout_s == 60
        assert not ctx.cancel.is_set()
