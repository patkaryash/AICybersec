"""Unit tests: db_sink event translation to the frozen snake_case vocabulary."""
from __future__ import annotations

from backend.services.db_sink import DatabaseEventSink, _persisted_event_type


def _sink():
    return DatabaseEventSink(lambda: None, scan_id="s", project_id="p")


class TestEventTranslation:
    def test_tool_started_translated(self):
        assert _persisted_event_type("tool.started", {}) == "tool_started"

    def test_tool_finished_ok_translated_to_completed(self):
        assert _persisted_event_type("tool.finished", {"status": "ok"}) == "tool_completed"

    def test_tool_finished_error_translated_to_failed(self):
        assert _persisted_event_type("tool.finished", {"status": "error"}) == "tool_failed"

    def test_tool_finished_timeout_translated_to_failed(self):
        assert _persisted_event_type("tool.finished", {"status": "timeout"}) == "tool_failed"

    def test_decision_proposed_translated(self):
        assert _persisted_event_type("decision.proposed", {}) == "agent_decision"

    def test_decision_rejected_translated(self):
        assert _persisted_event_type("decision.rejected", {}) == "agent_observation"

    def test_finding_recorded_translated(self):
        assert _persisted_event_type("finding.recorded", {}) == "finding_created"

    def test_scan_lifecycle_events_skipped(self):
        """The executor owns scan lifecycle events (right order/transaction);
        the runtime's run.* events are never persisted as-is."""
        for dot in ("run.started", "run.finished", "run.failed", "step.started"):
            assert _persisted_event_type(dot, {}) is None, dot

    def test_no_dot_notation_ever_persisted(self):
        """Every persisted type is snake_case (the frozen contract)."""
        runtime_events = [
            ("run.started", {}),
            ("step.started", {}),
            ("decision.proposed", {}),
            ("decision.rejected", {}),
            ("tool.started", {}),
            ("tool.finished", {"status": "ok"}),
            ("tool.finished", {"status": "error"}),
            ("finding.recorded", {}),
            ("run.finished", {"status": "finished"}),
            ("run.failed", {}),
        ]
        for event_type, data in runtime_events:
            persisted = _persisted_event_type(event_type, data)
            if persisted is not None:
                assert "." not in persisted, persisted
                assert "_" in persisted, persisted


class TestSinkProtocol:
    def test_sink_failure_never_raises(self):
        """A persistence failure must never break the agent loop."""

        class _BrokenFactory:
            def __call__(self):
                raise RuntimeError("db down")

        sink = DatabaseEventSink(_BrokenFactory(), scan_id="s", project_id="p")
        # must not raise
        sink.handle({"type": "tool.started", "step": 1, "data": {"tool": "nmap"}})
