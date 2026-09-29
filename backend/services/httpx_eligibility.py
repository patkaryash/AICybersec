"""Narrow run-local HTTPX authorization for promoted discovery hosts.

Phase 4C Step 5 correction: promotion must mean *HTTPX-only* eligibility,
never general authorization. The previous wiring derived a general
``Policy`` (original + promoted) and handed it to ``AgentRuntime``, which
made ``Nmap(app)`` / ``Nuclei(app)`` / arbitrary ``ToolCall(app)`` pass
validation merely because of promotion.

This module provides the narrow gate without touching ``AgentRuntime``
or ``SafetyValidator`` globally and without a second execution path:

- :class:`PromotedHttpxValidator` duck-matches ``SafetyValidator``
  (``registry`` / ``policy`` attributes + ``validate(decision, state)``)
  so ``AgentRuntime`` works unchanged. Non-HTTPX decisions delegate
  byte-for-byte to the original validator. HTTPX decisions pass only
  when every target host is originally authorized OR in the validated
  run-local ``eligible`` set. Schema, danger-cap, and ``check_extra``
  semantics are identical to ``SafetyValidator``.
- :func:`build_httpx_runtime_policy` derives the run-local ``Policy``
  copy used for ``ToolContext`` (the in-tool defense-in-depth recheck
  needs promoted hosts present for HTTPX to execute). The gate remains
  the validator: Nmap/Nuclei promoted calls are rejected before any
  tool sees them, so the broader context list cannot authorize them.

``eligible`` must already be hostname-only (see
``pipeline_planner.sanitize_promoted_hosts``); this module re-checks
membership by host-normalized comparison and never interprets DNS
answers, CNAMEs, redirects, or scanner output as authorization.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from agent_core.safety.policy import Policy, check_extra
from agent_core.schemas.actions import Decision, Finish, ToolCall
from agent_core.schemas.state import AgentState
from agent_core.safety.validator import SafetyValidator, ValidationOutcome


def build_httpx_runtime_policy(base_policy: Policy, eligible: list[str]) -> Policy:
    """Derive the run-local context Policy (original untouched).

    Union of original ``allowed_targets`` + eligible hostnames,
    host-normalized deduped. Needed ONLY so ``ToolContext`` lets the
    already validator-accepted HTTPX call past the in-tool recheck.
    """
    merged = list(base_policy.allowed_targets)
    seen = {Policy.normalize_target(t) for t in merged}
    for host in eligible or []:
        if not isinstance(host, str):
            continue
        norm = Policy.normalize_target(host)
        if norm not in seen:
            merged.append(host)
            seen.add(norm)
    return base_policy.model_copy(update={"allowed_targets": merged})


@dataclass
class PromotedHttpxValidator:
    """Narrow gate: original validator for everything except HTTPX.

    Attributes mirror ``SafetyValidator`` (``registry`` passthrough,
    ``policy`` is the ORIGINAL policy object, never a derived copy) so
    ownership/audit checks keep working.
    """

    base: SafetyValidator
    eligible_hosts: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        eligible = self.eligible_hosts or []
        self._eligible: set[str] = {
            norm
            for h in eligible
            if isinstance(h, str)
            for norm in [Policy.normalize_target(h)]
            if norm is not None
        }

    @property
    def registry(self):  # type: ignore[no-redef]
        return self.base.registry

    @property
    def policy(self):  # type: ignore[no-redef]
        return self.base.policy

    def validate(self, decision: Decision, state: AgentState) -> ValidationOutcome:
        if isinstance(decision, Finish):
            return self.base.validate(decision, state)
        if not isinstance(decision, ToolCall):
            return ValidationOutcome(accepted=False, reason="unsupported decision type")
        if decision.tool != "httpx":
            # Nmap / Nuclei / Subfinder / DNSX / mocks: EXACT original gate.
            # Promoted-only hosts stay rejected here unless independently
            # authorized by the original scan authorization.
            return self.base.validate(decision, state)
        return self._validate_httpx(decision, state)

    def _validate_httpx(self, decision: ToolCall, state: AgentState) -> ValidationOutcome:
        # Fast path: originally authorized HTTPX calls pass unchanged.
        base_outcome = self.base.validate(decision, state)
        if base_outcome.accepted:
            return base_outcome
        # Only an allowlist rejection may be rescued by eligibility;
        # schema / danger / extra rejections stay rejected.
        reason = (base_outcome.reason or "")
        if "not in the allowed targets list" not in reason:
            return base_outcome
        # Re-run the identical checks, with per-target allow = original OR eligible.
        if not self.registry.has(decision.tool):
            return ValidationOutcome(accepted=False, reason=f"unknown tool: {decision.tool!r}")
        tool = self.registry.get(decision.tool)
        try:
            params = tool.validate_params(decision.params)
        except ValidationError as exc:
            return ValidationOutcome(
                accepted=False,
                reason=f"invalid parameters for {decision.tool!r}: {exc.error_count()} error(s)",
            )
        if not self.base.policy.danger_allowed(tool):
            return ValidationOutcome(
                accepted=False,
                reason=(
                    f"danger level {tool.danger_level!r} exceeds policy cap "
                    f"{self.base.policy.max_danger!r}"
                ),
            )
        for target in SafetyValidator._extract_targets(tool, decision.params):
            if self.base.policy.target_allowed(target):
                continue
            norm = Policy.normalize_target(target if isinstance(target, str) else None)
            if norm is not None and norm in self._eligible:
                continue
            return ValidationOutcome(
                accepted=False,
                reason=f"target {target!r} is not in the allowed targets list",
            )
        extra_reason = check_extra(self.base.policy, state)
        if extra_reason:
            return ValidationOutcome(accepted=False, reason=extra_reason)
        return ValidationOutcome(accepted=True, tool=tool, validated_params=params)


__all__ = ["PromotedHttpxValidator", "build_httpx_runtime_policy"]
