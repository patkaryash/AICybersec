"""Model providers: the replaceable-model boundary (no parsing here)."""
from agent_core.providers.base import (
    Message,
    ModelProvider,
    ModelRequest,
    ModelResponse,
)
from agent_core.providers.factory import build_provider
from agent_core.providers.mock import MockModelProvider
from agent_core.providers.openai_compatible import OpenAICompatibleProvider

__all__ = [
    "Message",
    "MockModelProvider",
    "ModelProvider",
    "ModelRequest",
    "ModelResponse",
    "OpenAICompatibleProvider",
    "build_provider",
]
