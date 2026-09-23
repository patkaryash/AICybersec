"""Composition root for the FastAPI backend.

This is the ONLY place that knows how to build the agent stack.  The
backend embeds agent_core in-process (no microservice).  agent_core
itself never imports FastAPI - the dependency points this way only.

The initial implementation wires the mock/scripted stack so the API runs
without an LLM or real security tools.  Swapping in a real model later
means changing exactly this file (plus config), nothing in agent_core.
"""
from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field

from agent_core.config import get_settings
from agent_core.planner import ScriptedPlanner
from agent_core.runtime import AgentRuntime, InMemorySink
from agent_core.safety.policy import Policy, policy_from_env
from agent_core.safety.validator import SafetyValidator
from agent_core.state import JsonFileStore
from agent_core.tools.mocks import MockPortScan, MockWebProbe
from agent_core.tools.httpx import HTTPXTool
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


@dataclass
class ManagedRun:
    """In-memory handle for a running/finished run owned by this process."""

    state: object  # AgentState; kept loose to avoid importing schemas here
    cancel: threading.Event = field(default_factory=threading.Event)
    sink: InMemorySink = field(default_factory=InMemorySink)


class RunManager:
    """Owns run lifecycle inside the backend process.

    Deliberately simple: an in-memory registry plus a worker thread per
    run.  No database, no queue (approved scope).  A later persistence
    layer can wrap this without touching agent_core.
    """

    def __init__(self) -> None:
        self._runs: dict[str, ManagedRun] = {}
        self._lock = threading.Lock()

    def create_run(self, goal: str, targets: list[str], mode: str) -> str:
        settings = get_settings()
        store = JsonFileStore(settings.runs_dir)
        registry = build_registry()
        policy = build_policy(targets, mode)
        validator = SafetyValidator(registry, policy)
        planner = ScriptedPlanner(
            ScriptedPlanner.demo_script(targets[0] if targets else "demo.local")
        )
        sink = InMemorySink()

        runtime = AgentRuntime(
            planner=planner,
            registry=registry,
            validator=validator,
            store=store,
            events=[sink],
            policy=policy,
        )
        run_id = f"run-{uuid.uuid4().hex[:12]}"
        managed = ManagedRun(state=runtime.new_state(goal, run_id), sink=sink)
        with self._lock:
            self._runs[run_id] = managed
        thread = threading.Thread(
            target=self._execute, args=(runtime, managed), daemon=True
        )
        thread.start()
        return run_id

    def _execute(self, runtime: AgentRuntime, managed: ManagedRun) -> None:
        try:
            runtime.execute(managed.state, cancel=managed.cancel)
        except Exception as exc:  # keep the worker thread from dying silently
            managed.state.status = "failed"
            managed.state.error = str(exc)

    def get(self, run_id: str) -> ManagedRun | None:
        with self._lock:
            return self._runs.get(run_id)

    def runs(self) -> list[str]:
        with self._lock:
            return list(self._runs)


_manager: RunManager | None = None


def get_run_manager() -> RunManager:
    global _manager
    if _manager is None:
        _manager = RunManager()
    return _manager
