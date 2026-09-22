"""Model provider abstraction: the replaceable-model boundary.

Approved requirement 9: the development LLM must be replaceable with the
team's own trained security model through this interface, without changing
the agent core runtime.

Contract notes:
- The provider is DUMB: ``generate`` returns raw text. It never parses
  Decisions and never knows about tools at runtime.
- Prompts/assembly live in the planner layer, not here.
- Everything must work without credentials or network access for now.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass
class Message:
    """One conversation message. ``role`` is 'system' | 'user' | 'assistant'."""

    role: str
    content: str


@dataclass
class ModelRequest:
    """Input to any model provider implementation."""

    messages: list[Message]
    tool_schemas: list[dict[str, Any]] = field(default_factory=list)
    response_format: str = "json"  # decisions are expected as JSON text


@dataclass
class ModelResponse:
    """Raw completion. Parsing/validation happens OUTSIDE the provider."""

    raw_text: str


@runtime_checkable
class ModelProvider(Protocol):
    """Implement exactly this to plug in a new model (incl. your own)."""

    def generate(self, request: ModelRequest) -> ModelResponse: ...
