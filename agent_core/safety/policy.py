"""Safety policy: what a run is allowed to do.

Requirement 4 (minimum): allowed targets, max danger level, run mode,
max steps.  Rate limiting is intentionally NOT implemented - the
``check_extra`` extension point below is where it will live later.
"""
from __future__ import annotations

from urllib.parse import urlparse

from pydantic import BaseModel, Field

from agent_core.schemas.state import AgentState
from agent_core.schemas.tools import DangerLevel
from agent_core.tools.base import Tool

RunMode = str  # simple open string for now: "recon" | "lab" | ... (documented, not enforced)


class Policy(BaseModel):
    """Declarative permission set for one run."""

    allowed_targets: list[str] = Field(default_factory=list)
    max_danger: str = DangerLevel.ACTIVE_SCAN
    mode: str = "recon"
    max_steps: int = 12
    timeout_s: int = 60

    @staticmethod
    def normalize_target(target: str | None) -> str | None:
        """Reduce a tool param to its host so one allowlist covers
        host-shaped params ("demo.local") and URL-shaped params
        ("http://demo.local:8080/path").  Tools differ in what they take;
        the policy should stay host-scoped."""
        if target is None:
            return None
        t = str(target).strip()
        if "://" in t:
            parsed = urlparse(t)
            if parsed.hostname:
                return parsed.hostname.lower()
        return t.lower()

    def target_allowed(self, target: str | None) -> bool:
        """Host-normalized allowlist. Empty allowlist allows nothing."""
        normalized = self.normalize_target(target)
        if normalized is None:
            return False
        return normalized in {self.normalize_target(t) for t in self.allowed_targets}

    def danger_allowed(self, tool: Tool) -> bool:
        return not DangerLevel.exceeds(tool.danger_level, self.max_danger)


def policy_from_env(
    allowed_targets: list[str] | None = None,
    max_steps: int | None = None,
    max_danger: str | None = None,
    mode: str | None = None,
) -> Policy:
    """Build a Policy from explicit args with env fallbacks (via config)."""
    from agent_core.config import get_settings

    s = get_settings()
    return Policy(
        allowed_targets=(
            allowed_targets
            if allowed_targets is not None
            else s.allowed_targets_list()
        ),
        max_danger=max_danger or s.max_danger,
        mode=mode or s.default_mode,
        max_steps=max_steps or s.max_steps,
        timeout_s=s.tool_timeout_s,
    )


def check_extra(policy: Policy, state: AgentState) -> str | None:
    """Extension point for future checks (rate limiting, budgets, ...).

    Returns a rejection reason, or None if no extra rule objects.
    Current rules: none.  Do not remove - future checks plug in here.
    """
    return None
