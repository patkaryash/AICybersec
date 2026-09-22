"""Tool-facing schemas: what the model sees and what tools return."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class DangerLevel(str):
    """Classification of how intrusive a tool is.

    Kept as plain string constants (not an Enum) so JSON payloads carry
    simple strings and the ordering is explicit via RANK.
    """

    SAFE = "safe"                    # read-only against allowed targets
    ACTIVE_SCAN = "active_scan"      # sends traffic to the target
    INTRUSIVE = "intrusive"          # could alter or disrupt the target

    RANK: dict[str, int] = {SAFE: 0, ACTIVE_SCAN: 1, INTRUSIVE: 2}

    @classmethod
    def is_known(cls, value: str) -> bool:
        return value in cls.RANK

    @classmethod
    def rank(cls, value: str) -> int:
        return cls.RANK[value]

    @classmethod
    def exceeds(cls, value: str, cap: str) -> bool:
        """True when ``value`` is strictly more dangerous than ``cap``."""
        return cls.RANK[value] > cls.RANK[cap]


class ToolSpec(BaseModel):
    """Model-facing contract describing one tool.

    This is what the planner/model sees when deciding what to call.
    Requirement 3: name, description, input schema, danger level.
    """

    name: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    description: str
    input_schema: dict[str, Any] = Field(
        description="JSON Schema for the tool's parameters (from its Pydantic input model)"
    )
    danger_level: str
