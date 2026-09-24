"""Safety validator: the gate between the model and every tool execution.

Two stages (approved requirement 4):
  Stage 1 - schema: does the Decision parse and match a registered tool's
            input model?
  Stage 2 - policy: targets allowed? danger level within cap? extra rules?

A rejected Decision is NEVER executed; the rejection becomes an
Observation so the planner can react on the next step.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from agent_core.schemas.actions import Decision, Finish, ToolCall
from agent_core.safety.policy import Policy, check_extra
from agent_core.schemas.state import AgentState
from agent_core.tools.base import Tool
from agent_core.tools.registry import ToolRegistry


@dataclass
class ValidationOutcome:
    accepted: bool
    reason: str | None = None       # set when rejected
    tool: Tool | None = None        # resolved tool when accepted
    validated_params: Any = None    # Pydantic model instance when accepted


class SafetyValidator:
    def __init__(self, registry: ToolRegistry, policy: Policy) -> None:
        self.registry = registry
        self.policy = policy

    def validate(self, decision: Decision, state: AgentState) -> ValidationOutcome:
        if isinstance(decision, Finish):
            return ValidationOutcome(accepted=True)

        if isinstance(decision, ToolCall):
            # --- Stage 1: schema -------------------------------------
            if not self.registry.has(decision.tool):
                return ValidationOutcome(
                    accepted=False,
                    reason=f"unknown tool: {decision.tool!r}",
                )
            tool = self.registry.get(decision.tool)
            try:
                params = tool.validate_params(decision.params)
            except ValidationError as exc:
                return ValidationOutcome(
                    accepted=False,
                    reason=f"invalid parameters for {decision.tool!r}: {exc.error_count()} error(s)",
                )

            # --- Stage 2: policy -------------------------------------
            if not self.policy.danger_allowed(tool):
                return ValidationOutcome(
                    accepted=False,
                    reason=(
                        f"danger level {tool.danger_level!r} exceeds policy cap "
                        f"{self.policy.max_danger!r}"
                    ),
                )

            # Target extraction is tool-driven: ask the tool which param
            # identifies its target(s) so policy stays schema-agnostic.
            # Single-target tools use `target`/`url` (or `policy_target`);
            # multi-target tools (e.g. httpx `targets`) expose
            # `policy_targets(params) -> list`. EVERY entry must be allowed.
            for target in self._extract_targets(tool, decision.params):
                if not self.policy.target_allowed(target):
                    return ValidationOutcome(
                        accepted=False,
                        reason=(
                            f"target {target!r} is not in the allowed targets list"
                        ),
                    )

            extra_reason = check_extra(self.policy, state)
            if extra_reason:
                return ValidationOutcome(accepted=False, reason=extra_reason)

            return ValidationOutcome(
                accepted=True, tool=tool, validated_params=params
            )

        return ValidationOutcome(accepted=False, reason="unsupported decision type")

    @staticmethod
    def _extract_target(tool: Tool, params: dict[str, Any]) -> str | None:
        """Find the policy-relevant target from raw params.

        Conventions: params key ``target`` or ``url``.  Kept tiny and
        documented - a future tool with different semantics can override
        by exposing a ``policy_target(params)`` method. Multi-target
        tools should expose ``policy_targets(params)`` instead; see
        ``_extract_targets``.
        """
        override = getattr(tool, "policy_target", None)
        if callable(override):
            return override(params)
        if "target" in params:
            return str(params["target"])
        if "url" in params:
            return str(params["url"])
        return None

    @staticmethod
    def _extract_targets(tool: Tool, params: dict[str, Any]) -> list[str | None]:
        """All policy-relevant targets for a decision (each must be allowed)."""
        plural = getattr(tool, "policy_targets", None)
        if callable(plural):
            result = plural(params)
            if isinstance(result, list):
                return [str(t) if t is not None else None for t in result]
            return [str(result) if result is not None else None]
        if "targets" in params and isinstance(params["targets"], list):
            return [str(t) for t in params["targets"]]
        return [SafetyValidator._extract_target(tool, params)]
