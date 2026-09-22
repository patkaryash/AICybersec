"""Agent state schemas: AgentState, StepRecord, RunStatus."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

from agent_core.schemas.results import Finding, Observation

RunStatus = Literal["running", "finished", "failed", "cancelled"]


def utcnow() -> datetime:
    """Timezone-aware UTC timestamp (naive-UTC avoided on purpose)."""
    return datetime.now(timezone.utc)


class StepRecord(BaseModel):
    """One loop iteration, for state/trajectory reconstruction."""

    step: int
    decision: dict  # serialized Decision (tool_call or finish)
    observation: Observation | None = None
    rejected: bool = False
    rejection_reason: str | None = None
    started_at: datetime
    ended_at: datetime | None = None


class AgentState(BaseModel):
    """Complete, serializable state of one run.

    No hidden in-memory truth: the runtime works on this object and the
    store persists it, so a run can be inspected (and later resumed).
    """

    run_id: str
    goal: str
    status: RunStatus = "running"
    step: int = 0
    max_steps: int = 12
    observations: list[Observation] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    steps: list[StepRecord] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=utcnow)
    completed_at: datetime | None = None
    error: str | None = None

    def summary(self) -> dict:
        """Compact dict for API/UI consumption."""
        return {
            "run_id": self.run_id,
            "goal": self.goal,
            "status": self.status,
            "step": self.step,
            "max_steps": self.max_steps,
            "findings_count": len(self.findings),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "error": self.error,
        }
