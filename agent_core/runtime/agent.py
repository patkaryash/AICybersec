"""AgentRuntime: the synchronous decide -> validate -> execute loop.

This is the heart of agent_core.  It embeds the planner, safety
validator, tool registry, state store and event sink - all injected, all
mockable.  It stays single-threaded and synchronous on purpose (approved
requirement: no async complexity unless FastAPI integration requires it).

Loop (approved requirement 6):
    create state -> emit run.started ->
    per step: step.started -> decide -> decision.proposed ->
      [rejected: decision.rejected + rejection observation] ->
      tool.started -> execute -> tool.finished -> findings -> observation ->
      update state -> persist -> trajectory entry ->
    until Finish | max_steps | cancel | fatal error ->
    run.finished | run.failed
"""
from __future__ import annotations

import threading
import uuid
from typing import Sequence

from agent_core.planner.base import Planner
from agent_core.runtime.events import EventSink, make_event
from agent_core.safety.policy import Policy
from agent_core.safety.validator import SafetyValidator
from agent_core.schemas.actions import Decision, Finish, ToolCall
from agent_core.schemas.results import Observation
from agent_core.schemas.state import AgentState, RunStatus, StepRecord, utcnow
from agent_core.state.store import JsonFileStore, StateStore
from agent_core.tools.base import ToolContext
from agent_core.tools.registry import ToolRegistry

_STEP_RESULTS: dict[str, str] = {
    "finished": "run.finished",
    "failed": "run.failed",
    "cancelled": "run.finished",
}


class AgentRuntime:
    """Runs one goal to completion. Create a new instance per run."""

    def __init__(
        self,
        *,
        planner: Planner,
        registry: ToolRegistry,
        validator: SafetyValidator,
        store: StateStore,
        events: Sequence[EventSink],
        policy: Policy,
    ) -> None:
        self.planner = planner
        self.registry = registry
        self.validator = validator
        self.store = store
        self.events = list(events)
        self.policy = policy

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------
    def new_state(self, goal: str, run_id: str | None = None) -> AgentState:
        state = AgentState(
            run_id=run_id or f"run-{uuid.uuid4().hex[:12]}",
            goal=goal,
            max_steps=self.policy.max_steps,
        )
        self.store.save_state(state)
        return state

    def resume_state(self, run_id: str) -> AgentState:
        state = self.store.load_state(run_id)
        if state is None:
            raise KeyError(f"no persisted state for run {run_id!r}")
        return state

    def run(
        self,
        goal: str,
        *,
        run_id: str | None = None,
        cancel: threading.Event | None = None,
    ) -> AgentState:
        state = self.new_state(goal, run_id)
        return self.execute(state, cancel=cancel)

    def execute(
        self,
        state: AgentState,
        *,
        cancel: threading.Event | None = None,
    ) -> AgentState:
        """Drive an existing (fresh or resumed) state to completion."""
        cancel = cancel or threading.Event()
        self._emit("run.started", state, goal=state.goal, mode=self.policy.mode)

        while state.status == "running":
            if cancel.is_set():
                self._finish(state, "cancelled", summary="cancelled by request")
                break
            if state.step >= state.max_steps:
                self._finish(
                    state,
                    "failed",
                    error=f"max_steps ({state.max_steps}) reached without Finish",
                )
                break

            state.step += 1
            step_record = StepRecord(
                step=state.step, decision={}, started_at=utcnow()
            )
            self._emit("step.started", state)

            try:
                decision = self.planner.decide(state)
            except Exception as exc:  # planner failure = unrecoverable
                self._finish(state, "failed", error=f"planner error: {exc}")
                break

            step_record.decision = decision.model_dump(mode="json")
            self._emit(
                "decision.proposed", state, decision=step_record.decision
            )

            outcome = self.validator.validate(decision, state)

            obs: Observation | None = None
            finished_summary: str | None = None
            if not outcome.accepted:
                reason = outcome.reason or "rejected"
                step_record.rejected = True
                step_record.rejection_reason = reason
                self._emit("decision.rejected", state, reason=reason)
                obs = Observation.for_rejection(
                    state.step, getattr(decision, "tool", None), reason
                )
            elif isinstance(decision, Finish):
                finished_summary = decision.summary
            else:
                assert isinstance(decision, ToolCall)
                assert outcome.tool is not None
                obs = self._execute_tool(
                    state, decision, outcome.tool, outcome.validated_params
                )

            # Record EVERY step - including the terminal Finish decision,
            # which is exactly the label future training data needs.
            step_record.observation = obs
            step_record.ended_at = utcnow()
            state.steps.append(step_record)
            if obs is not None:
                state.observations.append(obs)
                for finding in obs.findings:
                    state.findings.append(finding)
                    self._emit("finding.recorded", state, finding=finding.model_dump(mode="json"))

            self.store.save_state(state)
            self.store.append_trajectory(
                JsonFileStore.trajectory_entry(
                    run_id=state.run_id,
                    step=state.step,
                    decision_raw=step_record.decision,
                    decision_validated=self._validated_view(decision),
                    rejected=step_record.rejected,
                    rejection_reason=step_record.rejection_reason,
                    tool=obs.tool if obs else None,
                    observation=obs,
                    started_at=step_record.started_at.isoformat(),
                    ended_at=step_record.ended_at.isoformat(),
                )
            )

            if finished_summary is not None:
                self._finish(state, "finished", summary=finished_summary)
                break

        return state

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------
    def _execute_tool(
        self,
        state: AgentState,
        decision: ToolCall,
        tool,
        validated_params,
    ) -> Observation:
        self._emit("tool.started", state, tool=tool.name)
        ctx = ToolContext(
            run_id=state.run_id,
            allowed_targets=list(self.policy.allowed_targets),
            timeout_s=self.policy.timeout_s,
        )
        try:
            result = tool.execute(validated_params, ctx)
        except Exception as exc:
            self._emit("tool.finished", state, tool=tool.name, status="error", summary=str(exc))
            return Observation(
                step=state.step,
                source="error",
                tool=tool.name,
                ok=False,
                summary=f"tool {tool.name} raised: {exc}",
                reason=str(exc),
            )

        self._emit(
            "tool.finished",
            state,
            tool=tool.name,
            status=result.status,
            summary=result.summary,
        )
        return Observation.from_tool_result(state.step, tool.name, result)

    def _finish(
        self,
        state: AgentState,
        status: RunStatus,
        *,
        summary: str | None = None,
        error: str | None = None,
    ) -> None:
        state.status = status
        state.completed_at = utcnow()
        state.error = error
        self.store.save_state(state)
        event_type = _STEP_RESULTS[status]
        payload = {
            "status": status,
            "findings_count": len(state.findings),
            "steps": state.step,
        }
        if summary is not None:
            payload["summary"] = summary
        if error is not None:
            payload["error"] = error
        self._emit(event_type, state, **payload)

    def _validated_view(self, decision: Decision) -> dict:
        """Executable content only - reasoning deliberately excluded."""
        if isinstance(decision, ToolCall):
            return {"kind": "tool_call", "tool": decision.tool, "params": decision.params}
        return {"kind": "finish", "summary": decision.summary}

    def _emit(self, event_type: str, state: AgentState, **data) -> None:
        event = make_event(event_type, state.run_id, step=state.step, **data)
        for sink in self.events:
            sink.handle(event)
