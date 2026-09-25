"""ScanManager: background scan execution (Phase 3).

Owns the only path from a persisted scan row to a running AgentRuntime:

    POST /scans -> scan_service.create_scan (queued, committed)
               -> ScanManager.submit (queued -> initializing -> running)
               -> worker thread: AgentRuntime.execute(...) with
                  DatabaseEventSink + JsonFileStore, then terminal mapping
               -> scan row completed | failed | cancelled

Design rules:
- agent_core is never modified and never imported by anything here
  except through its public interfaces (AgentRuntime, Policy,
  ToolRegistry builders, Planner).
- The planner only proposes; SafetyValidator (inside AgentRuntime)
  authorizes every tool call against the snapshot-derived allowlist.
- One worker thread per scan, bounded by a semaphore
  (max_concurrent_scans). Saturation -> 429, never a blocked request.
- Cancel is cooperative: request_cancel() sets the worker's event and
  the API transitions the row; AgentRuntime observes the event at the
  top of its loop. A mid-tool cancel waits out that tool's timeout
  (documented limitation, same as the CLI path).
- Threads are daemons; the process owns no distributed state (see the
  compose note about the single-backend deployment).
"""
from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import dataclass, field

from agent_core.runtime import AgentRuntime
from agent_core.safety.policy import Policy
from agent_core.safety.validator import SafetyValidator
from agent_core.state import JsonFileStore
from backend.core.errors import ApiError, ErrorCode
from backend.db.models import Scan
from backend.services.db_sink import DatabaseEventSink
from backend.services.pipeline_planner import PipelinePlanner
from backend.services.result_persistence import persist_assets_from_observations
from backend.services.scan_state import apply_transition

logger = logging.getLogger(__name__)

_ERROR_MAX_CHARS = 2000


@dataclass
class _ActiveRun:
    cancel: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread | None = None


class ScanManager:
    """Executes scans in background worker threads."""

    def __init__(
        self,
        *,
        session_factory=None,
        runs_dir: str = "runs",
        max_concurrent_scans: int = 2,
        default_max_steps: int = 12,
    ) -> None:
        from backend.db.session import get_session_factory

        # session_factory is a sessionmaker (default: the app's cached one);
        # sessions come from calling it. Stored, never called here, so the
        # same maker is safe to share across worker threads.
        self._sessions = session_factory or get_session_factory()
        self._runs_dir = runs_dir
        self._semaphore = threading.BoundedSemaphore(max_concurrent_scans)
        self._lock = threading.Lock()
        self._active: dict[uuid.UUID, _ActiveRun] = {}
        self._default_max_steps = default_max_steps

    # -- public API -------------------------------------------------------
    def submit(self, scan_id: uuid.UUID, *, planner=None) -> None:
        """Start background execution for a queued scan.

        ``planner`` is an injection point (tests pass a scripted or
        blocking planner); production callers omit it and the planner is
        built from the scan's mode. Raises ApiError (429) when all
        worker slots are busy - the scan stays queued for a later retry.
        """
        if not self._semaphore.acquire(blocking=False):
            raise ApiError(
                ErrorCode.TOO_MANY_SCANS,
                "Maximum concurrent scans reached; retry later.",
            )
        try:
            with self._sessions() as session:
                scan = session.get(Scan, scan_id)
                if scan is None:
                    raise ApiError(ErrorCode.SCAN_NOT_FOUND, "Scan does not exist.")
                if scan.status != "queued":
                    raise ApiError(
                        ErrorCode.INTERNAL_ERROR,
                        f"Cannot start scan from status {scan.status!r}.",
                    )
                apply_transition(scan, "initializing")
                apply_transition(scan, "running")
                session.commit()
                profile, mode = scan.profile, scan.mode
            cancel = threading.Event()
            thread = threading.Thread(
                target=self._run_scan,
                args=(scan_id, cancel, planner, profile, mode),
                daemon=True,
                name=f"scan-{str(scan_id)[:8]}",
            )
            with self._lock:
                self._active[scan_id] = _ActiveRun(cancel=cancel, thread=thread)
            thread.start()
        except Exception:
            self._semaphore.release()
            with self._lock:
                self._active.pop(scan_id, None)
            raise

    def request_cancel(self, scan_id: uuid.UUID) -> bool:
        """Signal a running worker to stop at the next loop iteration.

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

    def recover(self) -> dict[str, int]:
        """Startup recovery for scans interrupted by a backend restart.

        initializing/running -> failed (interrupted); cancelling ->
        cancelled; queued rows are left alone (never auto-started).
        Returns a count per outcome. Never raises.
        """
        outcomes = {"failed": 0, "cancelled": 0}
        try:
            with self._sessions() as session:
                from sqlalchemy import select

                from backend.db.models import Scan as ScanModel

                rows = session.scalars(
                    select(ScanModel).where(
                        ScanModel.status.in_(("initializing", "running", "cancelling"))
                    )
                ).all()
                for scan in rows:
                    try:
                        if scan.status == "cancelling":
                            apply_transition(scan, "cancelled")
                            outcomes["cancelled"] += 1
                        else:
                            apply_transition(
                                scan, "failed", error="Backend restarted during execution."
                            )
                            outcomes["failed"] += 1
                    except Exception:
                        logger.exception("recovery failed for scan %s", scan.id)
                session.commit()
        except Exception:
            logger.exception("scan recovery pass failed")
        return outcomes

    # -- worker -----------------------------------------------------------
    def _run_scan(self, scan_id: uuid.UUID, cancel: threading.Event, planner, profile: str, mode: str) -> None:
        try:
            self._execute(scan_id, cancel, planner, profile, mode)
        except Exception:
            logger.exception("scan worker failed for %s", scan_id)
            self._mark_failed(scan_id, "Scan worker encountered an internal error.")
        finally:
            with self._lock:
                self._active.pop(scan_id, None)
            self._semaphore.release()

    def _execute(self, scan_id, cancel, planner_override, profile, mode) -> None:
        from backend.deps import build_planner, build_registry

        with self._sessions() as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                logger.error("scan %s vanished before execution", scan_id)
                return
            snapshot = list(scan.target_snapshot or [])
            project_id = scan.project_id
            goal = scan.goal or f"Pipeline {scan.profile} security assessment."
            max_steps = scan.max_steps or self._default_max_steps
            tool_timeout = scan.tool_timeout_s
            scan_mode = scan.mode

        allowed = _snapshot_allowlist(snapshot)
        policy = Policy(
            allowed_targets=allowed,
            max_danger="active_scan",
            mode=scan_mode,
            max_steps=max_steps,
            timeout_s=tool_timeout,
        )
        registry = build_registry()
        if planner_override is not None:
            planner = planner_override
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
        final = runtime.execute(state, cancel=cancel)
        self._finish_scan(scan_id, final)

    def _finish_scan(self, scan_id: uuid.UUID, final) -> None:
        """Map the agent terminal status onto the scan row + persist assets."""
        try:
            with self._sessions() as session:
                scan = session.get(Scan, scan_id)
                if scan is None:
                    return
                if scan.status == "cancelling":
                    # A requested cancellation wins over whatever the
                    # agent did last; artifacts are already persisted.
                    apply_transition(scan, "cancelled")
                elif final.status == "finished":
                    apply_transition(scan, "completed")
                elif final.status == "cancelled":
                    if scan.status != "cancelled":
                        apply_transition(scan, "cancelled")
                else:  # failed (or anything unexpected -> failed, fail-closed)
                    error = getattr(final, "error", None) or "Agent run failed."
                    apply_transition(scan, "failed", error=str(error)[:_ERROR_MAX_CHARS])
                try:
                    persist_assets_from_observations(
                        session, scan=scan, observations=getattr(final, "observations", [])
                    )
                except Exception:
                    logger.exception("asset persistence failed for scan %s", scan_id)
                session.commit()
        except Exception:
            logger.exception("terminal mapping failed for scan %s", scan_id)

    def _mark_failed(self, scan_id: uuid.UUID, error: str) -> None:
        try:
            with self._sessions() as session:
                scan = session.get(Scan, scan_id)
                if scan is None or scan.status in ("completed", "failed", "cancelled"):
                    return
                try:
                    apply_transition(scan, "failed", error=error[:_ERROR_MAX_CHARS])
                except Exception:
                    return
                session.commit()
        except Exception:
            logger.exception("mark-failed failed for scan %s", scan_id)


def _snapshot_allowlist(snapshot: list[dict] | None) -> list[str]:
    """Host-form allowlist from host/url scope entries (fail-closed).

    CIDR entries are skipped: expanding networks is out of scope for
    Phase 3 v1, and the pipeline planner only drives host/url entries.
    An empty snapshot authorizes nothing (Policy rejects everything).
    """
    allowed: list[str] = []
    for entry in snapshot or []:
        if not isinstance(entry, dict) or entry.get("type") not in ("host", "url"):
            continue
        host = Policy.normalize_target(entry.get("value"))
        if host and host not in allowed:
            allowed.append(host)
    return allowed


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
