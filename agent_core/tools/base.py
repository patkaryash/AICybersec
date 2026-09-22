"""Tool abstraction: the ONLY way the agent touches security tooling.

Real security tools (nmap, httpx, nuclei, ZAP) will later implement this
same interface.  Approved requirement 6: there is NO shell tool, and real
tools must build fixed argv lists from validated Pydantic parameters -
never pass model-generated strings through a shell.
"""
from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from agent_core.schemas.results import ToolResult
from agent_core.schemas.tools import ToolSpec


class ToolContext(BaseModel):
    """Everything a tool is allowed to know about the run.

    ``allowed_targets`` is injected from policy - a tool cannot widen it.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    run_id: str
    allowed_targets: list[str] = Field(default_factory=list)
    timeout_s: int = 60
    cancel: threading.Event = Field(default_factory=threading.Event, exclude=True)


class Tool(ABC):
    """Base class for all tools registered in the ToolRegistry."""

    name: str
    description: str
    input_model: type[BaseModel]
    danger_level: str  # one of agent_core.schemas.tools.DangerLevel.*

    def spec(self) -> ToolSpec:
        """Model-facing contract for this tool."""
        return ToolSpec(
            name=self.name,
            description=self.description,
            input_schema=self.input_model.model_json_schema(),
            danger_level=self.danger_level,
        )

    def validate_params(self, params: dict[str, Any]) -> BaseModel:
        """Strictly validate raw params against this tool's input model."""
        return self.input_model.model_validate(params)

    @abstractmethod
    def execute(self, params: BaseModel, ctx: ToolContext) -> ToolResult:
        """Run the tool. Must never access the network in mock form."""
