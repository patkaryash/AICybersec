"""Stage 2 (M3-C): opt-in live-model smoke test.

Runs ONLY when explicitly enabled:

    AICYBERSEC_LIVE_MODEL_TEST=1
    AICYBERSEC_MODEL_BASE_URL=http://localhost:11434/v1  (or any endpoint)
    AICYBERSEC_MODEL_NAME=<model id>

Skipped in CI and in every normal run. Uses MOCK tools only - a live
model never triggers real Nmap/HTTPX/Nuclei execution here.
"""
from __future__ import annotations

import os

import pytest

from agent_core.planner import ModelPlanner
from agent_core.providers.factory import build_provider
from agent_core.schemas.actions import Finish, ToolCall
from agent_core.schemas.state import AgentState
from agent_core.tools.mocks import MockPortScan, MockWebProbe
from agent_core.tools.registry import ToolRegistry

_LIVE = os.getenv("AICYBERSEC_LIVE_MODEL_TEST") == "1"


def _live_settings():
    from agent_core.config import Settings

    return Settings()


requires_live_model = pytest.mark.skipif(
    not _LIVE,
    reason="live-model test needs AICYBERSEC_LIVE_MODEL_TEST=1 plus MODEL_BASE_URL/NAME",
)


@requires_live_model
def test_live_model_returns_a_valid_decision():
    from agent_core.config import get_settings

    get_settings.cache_clear()
    try:
        settings = _live_settings()
        assert settings.model_base_url, "set AICYBERSEC_MODEL_BASE_URL"
        provider = build_provider(settings)
        registry = ToolRegistry()
        registry.register(MockPortScan())
        registry.register(MockWebProbe())
        planner = ModelPlanner(provider, registry, allowed_targets=["demo.local"])
        state = AgentState(run_id="live", goal="Recon demo.local", max_steps=6)
        decision = planner.decide(state)
        assert isinstance(decision, (ToolCall, Finish))
    finally:
        get_settings.cache_clear()
