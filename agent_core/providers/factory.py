"""Provider factory: config-driven ModelProvider selection (M3-C).

All provider-specific construction lives here, inside providers/.
Callers (CLI, backend composition root) ask for a provider by settings
and receive something satisfying the ModelProvider protocol - they never
import concrete providers themselves.

Default is always MockModelProvider: a real endpoint is strictly opt-in
via AICYBERSEC_MODEL_PROVIDER=openai_compatible plus a base URL, so the
normal test suite never needs credentials or network access.
"""
from __future__ import annotations

from agent_core.providers.base import ModelProvider
from agent_core.providers.mock import MockModelProvider
from agent_core.providers.openai_compatible import OpenAICompatibleProvider


def build_provider(settings) -> ModelProvider:
    """Build the configured provider from agent_core Settings.

    settings is typed loosely to avoid importing config here (config
    imports nothing from providers, keeping the dependency one-way).
    """
    name = str(getattr(settings, "model_provider", "mock") or "mock").strip().lower()
    if name == "mock":
        return MockModelProvider()
    if name == "openai_compatible":
        base_url = str(getattr(settings, "model_base_url", "") or "").strip()
        if not base_url:
            raise ValueError(
                "AICYBERSEC_MODEL_BASE_URL must be set when "
                "AICYBERSEC_MODEL_PROVIDER=openai_compatible"
            )
        return OpenAICompatibleProvider(
            base_url=base_url,
            api_key=str(getattr(settings, "model_api_key", "") or ""),
            model=str(getattr(settings, "model_name", "") or "").strip() or "default",
            timeout_s=float(getattr(settings, "model_timeout_s", 60) or 60),
            max_response_chars=int(getattr(settings, "model_max_response_chars", 8000) or 8000),
        )
    raise ValueError(f"unknown model provider: {name!r} (expected mock|openai_compatible)")
