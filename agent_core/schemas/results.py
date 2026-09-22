"""Result schemas: ToolResult, Finding, Observation."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]
FindingStatus = Literal["open", "accepted_risk", "resolved", "false_positive"]


class Finding(BaseModel):
    """A normalized security finding - the product output of a run.

    Requirement 4: fields the report layer will consume; deliberately
    extensible (severity/confidence/status are open strings constrained by
    Literal for now; adding e.g. cvss later is a one-line change).
    """

    id: str = Field(
        description="Stable within a run: tool name + slug of title"
    )
    title: str
    severity: Severity = "info"
    target: str | None = None
    asset: str | None = None
    description: str | None = None
    evidence: dict[str, Any] | None = None
    tool: str
    confidence: Confidence = "medium"
    status: FindingStatus = "open"
    references: list[str] = Field(default_factory=list)


class ToolResult(BaseModel):
    """Raw outcome of one tool execution."""

    status: Literal["ok", "error", "timeout"]
    summary: str = ""
    data: dict[str, Any] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)


class Observation(BaseModel):
    """Normalized tool output (or rejection/error) fed back to the planner."""

    step: int
    source: Literal["tool", "rejected", "error"]
    tool: str | None = None
    ok: bool
    summary: str
    data: dict[str, Any] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    reason: str | None = Field(
        default=None,
        description="Rejection/error explanation when source != 'tool'",
    )

    @classmethod
    def from_tool_result(
        cls, step: int, tool: str, result: ToolResult
    ) -> "Observation":
        return cls(
            step=step,
            source="tool",
            tool=tool,
            ok=result.status == "ok",
            summary=result.summary,
            data=result.data,
            findings=result.findings,
        )

    @classmethod
    def for_rejection(
        cls, step: int, tool: str | None, reason: str
    ) -> "Observation":
        return cls(
            step=step,
            source="rejected",
            tool=tool,
            ok=False,
            summary=f"Decision rejected: {reason}",
            reason=reason,
        )
