"""ModelPlanner: model-backed Planner with strict Decision parsing (M3-A).

Boundary (the whole point of this file):

    structured observation/state
        -> ModelRequest (bounded, normalized, no raw dumps)
        -> ModelProvider.generate() (raw text only, never trusted)
        -> parse_decision() (existing strict schema, fail-closed)
        -> typed Decision (ToolCall | Finish)

The planner NEVER executes tools, NEVER calls SafetyValidator, and NEVER
touches ToolRegistry execution paths. Authorization stays in
SafetyValidator; orchestration stays in AgentRuntime. A provider or parse
failure raises ModelPlannerError, which the runtime already converts into
a controlled run failure with no execution.
"""
from __future__ import annotations

import json
from typing import Any

from agent_core.providers.base import Message, ModelProvider, ModelRequest
from agent_core.schemas.actions import Decision, parse_decision
from agent_core.schemas.state import AgentState
from agent_core.tools.registry import ToolRegistry

# Bounding caps so the model request stays deterministic and small.
MAX_GOAL_CHARS = 500
MAX_OBSERVATIONS = 5  # most recent only
MAX_FINDINGS = 10
MAX_SUMMARY_CHARS = 500
MAX_DATA_CHARS = 2000  # per-observation normalized data JSON

SYSTEM_PROMPT = """You are the planner for AICybersec, an AI-assisted penetration-testing platform.
You operate ONLY inside an explicitly authorized security-testing scope (controlled lab targets).
Rules:
- Select exactly one action from the provided tools, or finish the run.
- Use only the provided tool names with valid parameters. Never invent tools.
- You do not execute anything: you only propose. A separate safety layer authorizes every call.
- Never emit shell commands, binary paths, or flags. The tool name plus its typed params is the entire action surface.
- Respond with exactly one JSON object, either:
  {"kind": "tool_call", "tool": "<name>", "params": {...}, "reasoning": "<short reason>"} or
  {"kind": "finish", "summary": "<what was accomplished>"}."""


class ModelPlannerError(Exception):
    """Raised when the model cannot produce a valid Decision. Fail-closed."""


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + "...[truncated]"


def _bounded_observation(obs: Any) -> dict[str, Any]:
    """Compact one observation: summary + counts, data JSON capped."""
    try:
        data_json = json.dumps(obs.data, default=str)
    except (TypeError, ValueError):
        data_json = "{}"
    return {
        "step": obs.step,
        "source": obs.source,
        "tool": obs.tool,
        "ok": obs.ok,
        "summary": _truncate(str(obs.summary or ""), MAX_SUMMARY_CHARS),
        "data": _truncate(data_json, MAX_DATA_CHARS),
        "findings": [
            {"title": f.title, "severity": f.severity, "target": f.target}
            for f in (obs.findings or [])[:MAX_FINDINGS]
        ],
    }


def build_model_request(
    state: AgentState,
    registry: ToolRegistry,
    allowed_targets: list[str] | None = None,
) -> ModelRequest:
    """Assemble a bounded ModelRequest from normalized state (no raw dumps)."""
    tools = [
        {
            "name": spec.name,
            "description": spec.description,
            "danger_level": spec.danger_level,
            "input_schema": spec.input_schema,
        }
        for spec in registry.schemas()
    ]
    recent = [_bounded_observation(o) for o in state.observations[-MAX_OBSERVATIONS:]]
    known = [
        {"title": f.title, "severity": f.severity, "target": f.target, "tool": f.tool}
        for f in state.findings[-MAX_FINDINGS:]
    ]
    scope = {"allowed_targets": list(allowed_targets or [])}
    user_payload = {
        "goal": _truncate(state.goal, MAX_GOAL_CHARS),
        "step": state.step,
        "max_steps": state.max_steps,
        "scope": scope,
        "recent_observations": recent,
        "known_findings": known,
    }
    return ModelRequest(
        messages=[
            Message(role="system", content=SYSTEM_PROMPT),
            Message(role="user", content=json.dumps(user_payload, default=str)),
        ],
        tool_schemas=tools,
        response_format="json",
    )


class ModelPlanner:
    """Planner that asks a ModelProvider for the next Decision.

    Implements the existing Planner protocol, so AgentRuntime consumes it
    with zero changes. Strict parsing only: malformed JSON, schema
    violations, unknown tools, and invalid params all raise
    ModelPlannerError (the runtime records a controlled failure and
    executes nothing).
    """

    def __init__(
        self,
        provider: ModelProvider,
        registry: ToolRegistry,
        allowed_targets: list[str] | None = None,
    ) -> None:
        self.provider = provider
        self.registry = registry
        self.allowed_targets = list(allowed_targets or [])

    def decide(self, state: AgentState) -> Decision:
        request = build_model_request(state, self.registry, self.allowed_targets)
        try:
            response = self.provider.generate(request)
        except ModelPlannerError:
            raise
        except Exception as exc:
            raise ModelPlannerError(f"model provider failed: {exc}") from exc
        raw = response.raw_text or ""
        try:
            return parse_decision(raw)
        except ValueError as exc:
            raise ModelPlannerError(f"model returned an invalid Decision: {exc}") from exc
