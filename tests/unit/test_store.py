"""Unit tests: JsonFileStore + trajectory format + secret scrubbing."""
from __future__ import annotations

import json

from agent_core.schemas.results import Observation
from agent_core.state.store import JsonFileStore, scrub_secrets


class TestScrubSecrets:
    def test_redacts_secret_keys(self):
        data = {"params": {"target": "x", "api_key": "sk-123"}, "nested": {"token": "t"}}
        out = scrub_secrets(data)
        assert out["params"]["api_key"] == "[REDACTED]"
        assert out["nested"]["token"] == "[REDACTED]"
        assert out["params"]["target"] == "x"

    def test_redacts_in_lists(self):
        out = scrub_secrets([{"password": "hunter2"}])
        assert out == [{"password": "[REDACTED]"}]

    def test_non_dict_passthrough(self):
        assert scrub_secrets("plain") == "plain"


class TestJsonFileStore:
    def test_state_round_trip(self, tmp_path):
        store = JsonFileStore(tmp_path / "runs")
        from agent_core.schemas.state import AgentState

        state = AgentState(run_id="r1", goal="g")
        store.save_state(state)
        loaded = store.load_state("r1")
        assert loaded == state

    def test_trajectory_appends(self, tmp_path):
        store = JsonFileStore(tmp_path / "runs")
        entry = {
            "run_id": "r1",
            "step": 1,
            "decision_raw": {"kind": "tool_call", "tool": "t"},
            "decision_validated": {"kind": "tool_call", "tool": "t"},
        }
        store.append_trajectory(entry)
        store.append_trajectory({**entry, "step": 2})
        lines = store.read_trajectory("r1")
        assert [e["step"] for e in lines] == [1, 2]

    def test_trajectory_requires_run_id(self, tmp_path):
        store = JsonFileStore(tmp_path / "runs")
        try:
            store.append_trajectory({"step": 1})
            raise AssertionError("expected ValueError")
        except ValueError:
            pass

    def test_trajectory_entry_shape(self):
        obs = Observation.for_rejection(1, "t", "bad target")
        entry = JsonFileStore.trajectory_entry(
            run_id="r1",
            step=1,
            decision_raw={"kind": "tool_call", "tool": "t", "reasoning": "why"},
            decision_validated={"kind": "tool_call", "tool": "t"},
            rejected=True,
            rejection_reason="bad target",
            tool="t",
            observation=obs,
            started_at="2026-01-01T00:00:00+00:00",
            ended_at="2026-01-01T00:00:01+00:00",
        )
        assert entry["decision_raw"]["reasoning"] == "why"
        assert "reasoning" not in entry["decision_validated"]  # never executable
        assert entry["rejected"] is True
        assert entry["observation"]["source"] == "rejected"
        assert json.dumps(entry)  # JSON-serializable
