"""State persistence: StateStore protocol and JsonFileStore.

Layout per run:
    runs/<run_id>/state.json        latest AgentState (overwritten)
    runs/<run_id>/trajectory.jsonl  one JSON line per step (append-only)

Requirement 7: trajectory entries carry enough context to later become
training/evaluation data, and secrets must not be logged.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol

from agent_core.schemas.results import Observation
from agent_core.schemas.state import AgentState

REDACTED = "[REDACTED]"

# Keys that must never reach disk. Extend deliberately, not speculatively.
_SECRET_KEYS = {
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "credentials",
    "private_key",
    "session_id",
}


def scrub_secrets(obj: Any) -> Any:
    """Recursively replace secret-looking keys' values with [REDACTED]."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and k.lower() in _SECRET_KEYS:
                out[k] = REDACTED
            else:
                out[k] = scrub_secrets(v)
        return out
    if isinstance(obj, list):
        return [scrub_secrets(x) for x in obj]
    return obj


class StateStore(Protocol):
    def save_state(self, state: AgentState) -> None: ...
    def append_trajectory(self, entry: dict) -> None: ...


class JsonFileStore:
    """Filesystem-backed store. Synchronous, dependency-free."""

    def __init__(self, runs_dir: Path | str) -> None:
        self.runs_dir = Path(runs_dir)
        self.runs_dir.mkdir(parents=True, exist_ok=True)

    def run_dir(self, run_id: str) -> Path:
        d = self.runs_dir / run_id
        d.mkdir(parents=True, exist_ok=True)
        return d

    def save_state(self, state: AgentState) -> None:
        path = self.run_dir(state.run_id) / "state.json"
        payload = scrub_secrets(state.model_dump(mode="json"))
        path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    def load_state(self, run_id: str) -> AgentState | None:
        path = self.runs_dir / run_id / "state.json"
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return AgentState.model_validate(data)

    def append_trajectory(self, entry: dict) -> None:
        run_id = entry.get("run_id")
        if not run_id:
            raise ValueError("trajectory entry requires run_id")
        path = self.run_dir(run_id) / "trajectory.jsonl"
        payload = scrub_secrets(entry)
        with path.open("a", encoding="utf-8") as f:
            f.write(
                json.dumps(payload, ensure_ascii=False, default=str) + "\n"
            )

    def read_trajectory(self, run_id: str) -> list[dict]:
        path = self.runs_dir / run_id / "trajectory.jsonl"
        if not path.exists():
            return []
        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    @staticmethod
    def trajectory_entry(
        *,
        run_id: str,
        step: int,
        decision_raw: dict,
        decision_validated: dict,
        rejected: bool = False,
        rejection_reason: str | None = None,
        tool: str | None = None,
        observation: Observation | None = None,
        started_at: str | None = None,
        ended_at: str | None = None,
    ) -> dict:
        """Training/eval-oriented record of one step.

        decision_raw   = decision exactly as proposed (incl. reasoning)
        validated      = executable content only (kind, tool, params)
        observation    = normalized outcome summary fed back to the planner
        """
        entry = {
            "run_id": run_id,
            "step": step,
            "started_at": started_at,
            "ended_at": ended_at,
            "decision_raw": decision_raw,
            "decision_validated": decision_validated,
            "rejected": rejected,
            "rejection_reason": rejection_reason,
            "tool": tool,
            "observation": None
            if observation is None
            else {
                "source": observation.source,
                "tool": observation.tool,
                "ok": observation.ok,
                "summary": observation.summary,
                "data": observation.data,
                "findings": [f.model_dump() for f in observation.findings],
                "reason": observation.reason,
            },
        }
        return scrub_secrets(entry)
