"""MockModelProvider: deterministic, offline, credential-free."""
from __future__ import annotations

from agent_core.providers.base import ModelRequest, ModelResponse


class MockModelProvider:
    """Deterministic provider used for tests and demos.

    It never touches the network and needs no API key.  With no queued
    responses it echoes back the last user message (legacy behavior);
    tests for ModelPlanner queue exact raw JSON strings to simulate
    ``ToolCall`` / ``Finish`` model output deterministically.
    """

    def __init__(self, responses: list[str] | None = None) -> None:
        self._responses: list[str] = list(responses) if responses else []

    def queue(self, raw_text: str) -> None:
        """Append one canned raw completion (FIFO)."""
        self._responses.append(raw_text)

    def generate(self, request: ModelRequest) -> ModelResponse:
        if self._responses:
            return ModelResponse(raw_text=self._responses.pop(0))
        last = request.messages[-1].content if request.messages else ""
        return ModelResponse(raw_text=last)
