"""MockModelProvider: deterministic, offline, credential-free."""
from __future__ import annotations

from agent_core.providers.base import ModelRequest, ModelResponse


class MockModelProvider:
    """Deterministic provider used for tests and demos.

    It never touches the network and needs no API key.  For now it simply
    echoes back the last user message as its "completion"; the scripted
    demo path uses the ScriptedPlanner directly, so this provider mainly
    exists to prove the ModelProvider boundary is consumable without a
    real LLM.
    """

    def generate(self, request: ModelRequest) -> ModelResponse:
        last = request.messages[-1].content if request.messages else ""
        return ModelResponse(raw_text=last)
