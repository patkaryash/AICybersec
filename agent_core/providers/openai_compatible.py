"""OpenAI-compatible provider - EXTENSION POINT ONLY (not wired yet).

This file documents how the team's future model (or any OpenAI-compatible
endpoint, including a locally hosted one) will be plugged in without
touching the agent core runtime.  It intentionally has no implementation,
no dependencies and no credential requirement.

Future shape (do not enable until approved):

    class OpenAICompatibleProvider:
        def __init__(self, base_url: str, api_key: str, model: str): ...
        def generate(self, request: ModelRequest) -> ModelResponse:
            # POST /chat/completions with request.messages and
            # request.tool_schemas; return raw text only.
            ...

Selection will happen in the composition root (backend/deps.py or the
CLI) driven by config - e.g. AICYBERSEC_PROVIDER=mock|openai_compatible.
The runtime never learns which model is behind the interface.
"""
from __future__ import annotations

from agent_core.providers.base import ModelRequest, ModelResponse


class OpenAICompatibleProvider:
    """Placeholder. Raises until a real implementation is approved."""

    def __init__(self, base_url: str, api_key: str, model: str) -> None:
        self.base_url = base_url
        self.api_key = api_key
        self.model = model

    def generate(self, request: ModelRequest) -> ModelResponse:
        raise NotImplementedError(
            "OpenAICompatibleProvider is an extension point only; "
            "no external LLM is integrated in the foundation."
        )
