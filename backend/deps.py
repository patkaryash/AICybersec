"""Composition root for the FastAPI backend.

This is the ONLY place that knows how to build the agent stack.  The
backend embeds agent_core in-process (no microservice).  agent_core
itself never imports FastAPI - the dependency points this way only.

The legacy /runs API and its RunManager were removed in the Phase 2
migration. build_registry/build_policy/build_planner remain: the Phase 3
ScanManager reuses them when wiring real security tools and the agent
loop.
"""
from __future__ import annotations

from agent_core.config import get_settings
from agent_core.planner import ModelPlanner, ScriptedPlanner
from agent_core.providers.factory import build_provider
from agent_core.safety.policy import Policy, policy_from_env
from agent_core.tools.httpx import HTTPXTool
from agent_core.tools.mocks import MockPortScan, MockWebProbe
from agent_core.tools.nmap import NmapTool
from agent_core.tools.nuclei import NucleiTool
from agent_core.tools.registry import ToolRegistry


def build_registry() -> ToolRegistry:
    """Mock tools + real tools (nmap, httpx, nuclei). Real scans still require allowlist."""
    registry = ToolRegistry()
    registry.register(MockPortScan())
    registry.register(MockWebProbe())
    registry.register(NmapTool())
    registry.register(HTTPXTool())
    registry.register(NucleiTool())
    return registry


def build_policy(targets: list[str], mode: str) -> Policy:
    return policy_from_env(allowed_targets=targets, mode=mode)


def build_planner(registry: ToolRegistry, targets: list[str]):
    """Select the planner from agent_core settings (M3-C).

    Default is the deterministic ScriptedPlanner, so the API runs
    without an LLM exactly as before. Setting
    AICYBERSEC_MODEL_PROVIDER=openai_compatible (plus base URL/model)
    switches runs to ModelPlanner + the real provider. Either way the
    planner only proposes Decisions; SafetyValidator authorizes them.
    """
    settings = get_settings()
    if str(settings.model_provider or "mock").strip().lower() == "openai_compatible":
        return ModelPlanner(
            build_provider(settings), registry, allowed_targets=list(targets)
        )
    return ScriptedPlanner(
        ScriptedPlanner.demo_script(targets[0] if targets else "demo.local")
    )
