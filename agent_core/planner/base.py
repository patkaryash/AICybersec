"""Planner abstraction: decides the next Decision given current state."""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from agent_core.schemas.actions import Decision
from agent_core.schemas.state import AgentState


@runtime_checkable
class Planner(Protocol):
    """Implement this to swap planning strategies.

    The two planned implementations:
      - ScriptedPlanner (deterministic, no model) - now
      - ModelPlanner (wraps a ModelProvider + prompt + parser) - later
    """

    def decide(self, state: AgentState) -> Decision: ...
