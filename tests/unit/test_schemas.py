"""Unit tests: schemas (actions, results)."""
from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from agent_core.schemas.actions import Finish, ToolCall, parse_decision
from agent_core.schemas.results import Finding, Observation, ToolResult


class TestDecisionParsing:
    def test_parse_tool_call(self):
        d = parse_decision('{"kind": "tool_call", "tool": "mock_port_scan", "params": {"target": "h"}}')
        assert isinstance(d, ToolCall)
        assert d.tool == "mock_port_scan"
        assert d.params == {"target": "h"}
        assert d.reasoning is None

    def test_parse_tool_call_with_reasoning(self):
        d = parse_decision(
            '{"kind": "tool_call", "tool": "t", "params": {}, "reasoning": "why"}'
        )
        assert d.reasoning == "why"

    def test_parse_finish(self):
        d = parse_decision('{"kind": "finish", "summary": "done"}')
        assert isinstance(d, Finish)
        assert d.summary == "done"

    def test_reject_invalid_json(self):
        with pytest.raises(ValueError, match="not valid JSON"):
            parse_decision("{not json")

    def test_reject_non_object(self):
        with pytest.raises(ValueError, match="JSON object"):
            parse_decision('["tool_call"]')

    def test_reject_unknown_kind(self):
        with pytest.raises(ValueError, match="does not match the schema"):
            parse_decision('{"kind": "delete_everything"}')

    def test_reject_missing_tool(self):
        with pytest.raises(ValueError):
            parse_decision('{"kind": "tool_call", "params": {}}')

    def test_reject_finish_without_summary(self):
        # summary is required (no default) - must fail loudly
        with pytest.raises(ValueError):
            parse_decision('{"kind": "finish"}')

    def test_extra_keys_are_rejected(self):
        with pytest.raises(ValueError):
            parse_decision(
                '{"kind": "tool_call", "tool": "t", "params": {}, "shell": "rm -rf /"}'
            )


class TestFindingSerialization:
    def _finding(self, **overrides):
        base = dict(
            id="mock_web_probe:missing-security-header-mock-",
            title="Missing security header (mock)",
            severity="medium",
            target="demo.local",
            asset="http://demo.local",
            description="synthetic",
            evidence={"missing_header": "Content-Security-Policy"},
            tool="mock_web_probe",
            confidence="high",
            status="open",
            references=["https://owasp.org"],
        )
        base.update(overrides)
        return Finding(**base)

    def test_round_trip_json(self):
        f = self._finding()
        data = json.loads(f.model_dump_json())
        assert Finding(**data) == f

    def test_defaults(self):
        f = Finding(id="x", title="t", tool="mock")
        assert f.severity == "info"
        assert f.confidence == "medium"
        assert f.status == "open"
        assert f.references == []

    def test_reject_bad_severity(self):
        with pytest.raises(ValidationError):
            self._finding(severity="catastrophic")

    def test_reject_bad_confidence(self):
        with pytest.raises(ValidationError):
            self._finding(confidence="absolute")

    def test_reject_bad_status(self):
        with pytest.raises(ValidationError):
            self._finding(status="weird")


class TestObservation:
    def test_from_tool_result(self):
        r = ToolResult(status="ok", summary="fine", data={"a": 1})
        obs = Observation.from_tool_result(3, "mock_port_scan", r)
        assert obs.step == 3
        assert obs.source == "tool"
        assert obs.ok is True
        assert obs.summary == "fine"
        assert obs.data == {"a": 1}

    def test_for_rejection(self):
        obs = Observation.for_rejection(2, "mock_port_scan", "target not allowed")
        assert obs.source == "rejected"
        assert obs.ok is False
        assert obs.reason == "target not allowed"
        assert obs.summary.startswith("Decision rejected")
