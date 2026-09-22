"""ScriptedPlanner: deterministic decision sequence, no model involved."""
from __future__ import annotations

from agent_core.schemas.actions import Decision, Finish, ToolCall
from agent_core.schemas.state import AgentState


class ScriptPlannerExhausted(Exception):
    """Raised when the script is exhausted without a Finish decision."""


class ScriptedPlanner:
    """Replays a predefined list of Decisions.

    Typical demo script:
        1. ToolCall(mock_port_scan)
        2. ToolCall(mock_web_probe)
        3. Finish(summary=...)

    If the script runs out before a Finish, the planner raises so the
    runtime fails the run loudly instead of silently looping.
    """

    def __init__(self, decisions: list[Decision]) -> None:
        if not decisions:
            raise ValueError("ScriptedPlanner needs at least one decision")
        self._decisions = list(decisions)
        self._cursor = 0

    def decide(self, state: AgentState) -> Decision:
        if self._cursor >= len(self._decisions):
            raise ScriptPlannerExhausted(
                "ScriptedPlanner ran out of decisions before a Finish"
            )
        decision = self._decisions[self._cursor]
        self._cursor += 1
        return decision

    @staticmethod
    def demo_script(goal_target: str) -> list[Decision]:
        """The canonical 3-step demo: scan -> probe -> finish."""
        return [
            ToolCall(
                tool="mock_port_scan",
                params={"target": goal_target},
                reasoning="Start with a port scan to map exposed services.",
            ),
            ToolCall(
                tool="mock_web_probe",
                params={"url": f"http://{goal_target}"},
                reasoning="Port scan showed HTTP; probe the web surface.",
            ),
            Finish(
                summary=(
                    "Recon complete: mapped open ports and web headers "
                    f"for {goal_target}. Findings recorded."
                )
            ),
        ]
