"""ScanManager: background scan execution (Phase 3).

Owns the only path from a persisted scan row to a running AgentRuntime:

    POST /scans -> scan_service.create_scan (queued, committed)
               -> ScanManager.submit (pool submission; NO DB writes)
               -> worker: re-read scan -> confirm queued (race-safe) ->
                  queued->initializing -> scope resolution + revalidation ->
                  initializing->running -> AgentRuntime.execute(...) with
                  DatabaseEventSink + per-scan tool instances ->
                  terminal mapping + assets + ToolRun enrichment

Design rules:
- agent_core is never modified and never imported by anything here
  except through its public interfaces (AgentRuntime, Policy,
  SafetyValidator, Tool implementations, Planner).
- The planner only proposes; SafetyValidator (inside AgentRuntime)
  authorizes every tool call against the snapshot-derived allowlist
  (host/url entries + forward-DNS resolutions; see scope_resolution).
- Bounded concurrency: ThreadPoolExecutor(max_workers=
  max_concurrent_scans). Saturation NEVER rejects a scan - excess scans
  wait in the pool queue (FIFO) and run when a worker frees.
- The worker RE-READS the scan and confirms status == queued before
  executing (race-safe against cancel/recovery/duplicate scheduling).
- Cancel is cooperative: request_cancel() sets the worker's event; the
  runner (per-scan tool instances) polls it every ~100ms and kills the
  process group; AgentRuntime observes it at the top of its loop.
- Tools run sequentially within one scan; one subprocess at a time.
- Threads are daemon-backed pool workers; the process owns no
  distributed state (the in-memory cancellation registry is NOT a
  multi-process coordination mechanism - see the compose note about the
  single-backend deployment).
"""
from __future__ import annotations

import logging
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from agent_core.runtime import AgentRuntime
from agent_core.safety.policy import Policy
from agent_core.safety.validator import SafetyValidator
from agent_core.state import JsonFileStore
from backend.core.errors import ApiError, ErrorCode
from backend.db.models import Scan, ToolRun
from backend.services.db_sink import DatabaseEventSink
from backend.services.event_service import record_event
from backend.services.pipeline_planner import PipelinePlanner
from backend.services.result_persistence import persist_assets_from_observations
from backend.services.scope_resolution import resolve_scope
from backend.services.scan_state import apply_transition
from backend.services.tool_runner import RunRecorder, make_cancelling_runner

logger = logging.getLogger(__name__)

_ERROR_MAX_CHARS = 2000
_RESTART_ERROR = "Backend restarted during scan."


@dataclass
class _ActiveRun:
    """Per-scan cancellation bookkeeping."""

    cancel: threading.Event = field(default_factory=threading.Event)
    planner: object | None = None  # injection point for tests
    submitted: bool = False


class ScanManager:
    """Executes scans on a bounded background worker pool."""

    def __init__(
        self,
        *,
        session_factory=None,
        runs_dir: str = "runs",
        max_concurrent_scans: int = 2,
        default_max_steps: int = 12,
        resolver=None,
    ) -> None:
        from backend.db.session import get_session_factory

        # session_factory is a sessionmaker (default: the app's cached one);
        # sessions come from calling it, so the maker is safe to share
        # across worker threads. Workers use their own short-lived
        # sessions - never the HTTP request's session.
        self._sessions = session_factory or get_session_factory()
        self._runs_dir = runs_dir
        self._pool = ThreadPoolExecutor(
            max_workers=max(1, max_concurrent_scans), thread_name_prefix="scan-worker"
        )
        self._lock = threading.Lock()
        self._active: dict[uuid.UUID, _ActiveRun] = {}
        self._default_max_steps = default_max_steps
        self._resolver = resolver  # injectable DNS resolver (hostname -> [ips])
        self._shutting_down = False

    # -- public API -------------------------------------------------------
    def submit(self, scan_id: uuid.UUID, *, planner=None) -> None:
        """Submit a queued scan for background execution.

        NEVER rejected for capacity: excess scans wait in the pool queue
        (FIFO) and execute when a worker frees. Idempotent: a duplicate
        submission for an already-active scan is a no-op. The worker
        re-reads the scan and confirms status == queued before executing
        (race-safe against cancel/recovery/duplicate scheduling).
        """
        with self._lock:
            if self._shutting_down:
                return
            if scan_id in self._active:
                return
            entry = _ActiveRun(planner=planner)
            self._active[scan_id] = entry
        self._pool.submit(self._run_scan, scan_id, entry)

    def request_cancel(self, scan_id: uuid.UUID) -> bool:
        """Signal the scan's worker (and its running subprocess) to stop.

        Returns True when a worker was signalled. The database transition
        (running -> cancelling) is owned by scan_service, not here.
        """
        with self._lock:
            active = self._active.get(scan_id)
        if active is None:
            return False
        active.cancel.set()
        return True

    def active_scan_ids(self) -> list[uuid.UUID]:
        with self._lock:
            return list(self._active)

    def recover(self, *, planner=None) -> dict[str, int]:
        """Startup recovery for scans interrupted by a backend restart.

        queued -> re-submitted (accepted, never started: honest
        continuation); initializing/running -> failed (interrupted);
        cancelling -> cancelled; terminal scans untouched. Idempotent:
        status-guarded transitions; repeated startups never re-execute
        terminal scans. Never raises.
        """
        outcomes = {"failed": 0, "cancelled": 0, "rescheduled": 0}
        try:
            with self._sessions() as session:
                from sqlalchemy import select

                rows = session.scalars(
                    select(Scan).where(
                        Scan.status.in_(
                            ("queued", "initializing", "running", "cancelling")
                        )
                    )
                ).all()
                queued_ids = []
                for scan in rows:
                    try:
                        if scan.status == "queued":
                            queued_ids.append(scan.id)
                        elif scan.status == "cancelling":
                            apply_transition(scan, "cancelled")
                            record_event(
                                session,
                                scan_id=scan.id,
                                event_type="scan_status_changed",
                                data={"from": "cancelling", "to": "cancelled"},
                            )
                            outcomes["cancelled"] += 1
                        else:
                            apply_transition(scan, "failed", error=_RESTART_ERROR)
                            record_event(
                                session,
                                scan_id=scan.id,
                                event_type="scan_failed",
                                data={"status": "failed", "error": _RESTART_ERROR},
                            )
                            outcomes["failed"] += 1
                    except Exception:
                        logger.exception("recovery failed for scan %s", scan.id)
                session.commit()
            for scan_id in queued_ids:
                self.submit(scan_id, planner=planner)
                outcomes["rescheduled"] += 1
        except Exception:
            logger.exception("scan recovery pass failed")
        return outcomes

    def shutdown(self) -> None:
        """Stop accepting new scan work and shut the pool down.

        Queued futures are cancelled; running workers are daemon-backed
        and finish or die with the process (startup recovery handles
        interrupted scans on the next boot). The in-memory cancellation
        registry is single-process only.
        """
        with self._lock:
            self._shutting_down = True
        self._pool.shutdown(wait=False, cancel_futures=True)

    # -- worker -----------------------------------------------------------
    def _run_scan(self, scan_id: uuid.UUID, entry: _ActiveRun) -> None:
        try:
            self._execute(scan_id, entry)
        except Exception:
            logger.exception("scan worker failed for %s", scan_id)
            self._mark_failed(scan_id, "Scan worker encountered an internal error.")
        finally:
            with self._lock:
                self._active.pop(scan_id, None)

    def _execute(self, scan_id: uuid.UUID, entry: _ActiveRun) -> None:
        from backend.deps import build_planner

        # --- TX1: load + confirm queued + queued->initializing ----------
        with self._sessions() as session:
            scan = session.get(Scan, scan_id)
            # Race-safe abort (cancel/recovery/duplicate scheduling):
            # only a still-queued scan proceeds.
            if scan is None:
                logger.error("scan %s vanished before execution", scan_id)
                return
            if scan.status != "queued":
                logger.info("scan %s no longer queued (%s); aborting", scan_id, scan.status)
                return
            apply_transition(scan, "initializing")
            record_event(
                session,
                scan_id=scan_id,
                event_type="scan_started",
                data={
                    "profile": scan.profile,
                    "mode": scan.mode,
                    "goal": scan.goal,
                },
            )
            record_event(
                session,
                scan_id=scan_id,
                event_type="scan_status_changed",
                data={"from": "queued", "to": "initializing"},
            )
            session.commit()
            snapshot = list(scan.target_snapshot or [])
            project_id = scan.project_id
            goal = scan.goal or f"Pipeline {scan.profile} security assessment."
            max_steps = scan.max_steps or self._default_max_steps
            tool_timeout = scan.tool_timeout_s
            scan_mode = scan.mode
            profile = scan.profile

        # --- scope resolution + revalidation (authorization anchor) ------
        # The snapshot is the ONLY authorization source; the resolved
        # allowlist adds forward-DNS resolutions of authorized hostnames
        # (deterministic provenance - never scanner observation).
        allowed = resolve_scope(snapshot, resolver=self._resolver)

        # --- TX2: initializing -> running --------------------------------
        with self._sessions() as session:
            scan = session.get(Scan, scan_id)
            if scan is None or scan.status != "initializing":
                # cancelled while initializing (race) -> leave terminal
                return
            apply_transition(scan, "running")
            record_event(
                session,
                scan_id=scan_id,
                event_type="scan_status_changed",
                data={"from": "initializing", "to": "running"},
            )
            session.commit()

        # --- execute (NO transaction open while tools run) ----------------
        policy = Policy(
            allowed_targets=allowed,
            max_danger="active_scan",
            mode=scan_mode,
            max_steps=max_steps,
            timeout_s=tool_timeout,
        )
        recorder = RunRecorder()
        registry = self._build_per_scan_registry(scan_id, entry.cancel, recorder)
        if entry.planner is not None:
            planner = entry.planner
        elif scan_mode == "agent":
            planner = build_planner(registry, allowed)
        else:
            planner = PipelinePlanner(profile, snapshot, max_steps=max_steps)
        runtime = AgentRuntime(
            planner=planner,
            registry=registry,
            validator=SafetyValidator(registry, policy),
            store=JsonFileStore(self._runs_dir),
            events=[
                DatabaseEventSink(
                    self._sessions,
                    scan_id=scan_id,
                    project_id=project_id,
                    initiated_by=scan_mode,
                )
            ],
            policy=policy,
        )
        state = runtime.new_state(goal, run_id=str(scan_id))
        final = runtime.execute(state, cancel=entry.cancel)

        # --- TX4: terminal mapping + assets + ToolRun enrichment ----------
        self._finish_scan(scan_id, final, recorder)

    def _build_per_scan_registry(self, scan_id: uuid.UUID, cancel: threading.Event, recorder: RunRecorder):
        """Per-scan tool instances bound to THIS scan's cancel event.

        Per-scan instances are what keep cancellation events from leaking
        between scans; the shared general-purpose registry is never used
        as an execution path. The spill dir is a backend-controlled path
        from trusted UUIDs - never user input.
        """
        from agent_core.tools.httpx import HTTPXTool
        from agent_core.tools.mocks import MockPortScan, MockWebProbe
        from agent_core.tools.nmap import NmapTool
        from agent_core.tools.nuclei import NucleiTool
        from agent_core.tools.registry import ToolRegistry

        spill_dir = str(Path(self._runs_dir) / str(scan_id))
        runner = make_cancelling_runner(cancel, spill_dir=spill_dir, recorder=recorder)
        registry = ToolRegistry()
        registry.register(MockPortScan())
        registry.register(MockWebProbe())
        registry.register(NmapTool(runner=runner))
        registry.register(HTTPXTool(runner=runner))
        registry.register(NucleiTool(runner=runner))
        return registry

    def _finish_scan(self, scan_id: uuid.UUID, final, recorder: RunRecorder) -> None:
        """Terminal mapping + asset persistence + ToolRun enrichment."""
        try:
            with self._sessions() as session:
                scan = session.get(Scan, scan_id)
                if scan is None:
                    return
                if scan.status in ("completed", "failed", "cancelled"):
                    return  # terminal already (cancel won the race)
                prev_status = scan.status
                if scan.status == "cancelling":
                    # A requested cancellation wins over whatever the
                    # agent did last; artifacts are already persisted.
                    apply_transition(scan, "cancelled")
                elif final.status == "finished":
                    apply_transition(scan, "completed")
                elif final.status == "cancelled":
                    apply_transition(scan, "cancelled")
                else:  # failed (or anything unexpected -> failed, fail-closed)
                    error = getattr(final, "error", None) or "Agent run failed."
                    apply_transition(scan, "failed", error=str(error)[:_ERROR_MAX_CHARS])

                record_event(
                    session,
                    scan_id=scan_id,
                    event_type="scan_status_changed",
                    data={"from": prev_status, "to": scan.status},
                )
                terminal_event = {
                    "completed": "scan_completed",
                    "failed": "scan_failed",
                    "cancelled": "scan_cancelled",
                }[scan.status]
                record_event(
                    session,
                    scan_id=scan_id,
                    event_type=terminal_event,
                    data={
                        "status": scan.status,
                        "error": scan.error,
                    },
                )
                try:
                    persist_assets_from_observations(
                        session, scan=scan, observations=getattr(final, "observations", [])
                    )
                except Exception:
                    logger.exception("asset persistence failed for scan %s", scan_id)
                self._enrich_tool_runs(session, scan_id, recorder)
                session.commit()
        except Exception:
            logger.exception("terminal mapping failed for scan %s", scan_id)

    def _enrich_tool_runs(self, session, scan_id: uuid.UUID, recorder: RunRecorder) -> None:
        """Apply the runner recorder's audit captures to the ToolRun rows.

        - argv / exit_code / capped raw output / stderr: audit data
          (persisted; never exposed through the API).
        - Process-level outcome overrides: a cancelled run sets
          ToolRun.status = cancelled (the tool itself reports error; it
          has no cancel concept); a timed-out run stays timeout.
        """
        for tool in ("nmap", "httpx", "nuclei"):
            records = recorder.records_for(tool)
            if not records:
                continue
            rows = (
                session.query(ToolRun)
                .filter(ToolRun.scan_id == scan_id, ToolRun.tool == tool)
                .order_by(ToolRun.created_at)
                .all()
            )
            for row, record in zip(rows, records):
                row.argv = record.argv
                row.exit_code = record.exit_code
                row.raw_output = record.raw_output or None
                row.stderr = record.stderr or None
                if record.outcome in ("cancelled", "timeout"):
                    row.status = record.outcome

    def _mark_failed(self, scan_id: uuid.UUID, error: str) -> None:
        try:
            with self._sessions() as session:
                scan = session.get(Scan, scan_id)
                if scan is None or scan.status in ("completed", "failed", "cancelled"):
                    return
                try:
                    apply_transition(scan, "failed", error=error[:_ERROR_MAX_CHARS])
                    record_event(
                        session,
                        scan_id=scan_id,
                        event_type="scan_failed",
                        data={"status": "failed", "error": error[:_ERROR_MAX_CHARS]},
                    )
                except Exception:
                    return
                session.commit()
        except Exception:
            logger.exception("mark-failed failed for scan %s", scan_id)


_manager: ScanManager | None = None
_manager_lock = threading.Lock()


def get_scan_manager() -> ScanManager:
    """Process-wide ScanManager built from backend settings."""
    global _manager
    if _manager is None:
        with _manager_lock:
            if _manager is None:
                from backend.core.config import get_backend_settings

                settings = get_backend_settings()
                _manager = ScanManager(
                    runs_dir=settings.runs_dir,
                    max_concurrent_scans=settings.max_concurrent_scans,
                )
    return _manager
