"""Decision schemas: the closed set of actions the model/planner may emit.

Safety property: a Decision is a discriminated union of exactly two shapes
(``tool_call`` and ``finish``).  There is nothing else the model can say,
and nothing else the runtime will ever execute.

NOTE (approved requirement 5): ``ToolCall.reasoning`` exists only for
trajectory/debugging purposes.  Execution must never depend on it - the
executable content of a ToolCall is exactly (kind, tool, params).
"""
from __future__ import annotations

import json
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError


class ToolCall(BaseModel):
    """A request to execute one registered tool with validated parameters."""

    model_config = ConfigDict(extra="forbid")  # no smuggled keys, ever

    kind: Literal["tool_call"] = "tool_call"
    tool: str = Field(min_length=1, description="Registered tool name")
    params: dict[str, Any] = Field(default_factory=dict)
    reasoning: str | None = Field(
        default=None,
        description="Debugging/trajectory only. NEVER used for execution.",
    )


class Finish(BaseModel):
    """End the run with a final summary."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["finish"] = "finish"
    summary: str  # required: a run must end with an explicit summary


Decision = Annotated[ToolCall | Finish, Field(discriminator="kind")]

_DECISION_ADAPTER: TypeAdapter = TypeAdapter(Decision)


def parse_decision(raw: str) -> Decision:
    """Parse raw model/planner text into a validated Decision.

    Kept in the schemas layer so every caller (planner, tests, future
    providers) shares one parser and one error type.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Decision is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("Decision must be a JSON object")
    try:
        return _DECISION_ADAPTER.validate_python(data)
    except ValidationError as exc:
        raise ValueError(f"Decision does not match the schema: {exc}") from exc
