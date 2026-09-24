"""Scan state machine: THE authoritative transition implementation.

One place defines valid transitions and the DB fields each transition
changes; invalid transitions raise ScanStateError (API layer -> 409
SCAN_NOT_CANCELLABLE). The cancel endpoint (Phase 2) and the
ScanManager (Phase 3) both go through this module - scan status is
never changed outside it.

Valid flow:
    queued -> initializing -> running -> {completed | failed | cancelling}
    cancelling -> cancelled
    cancellation is also permitted directly from queued/initializing
    (no execution exists to interrupt in Phase 2)

Terminal states: completed, failed, cancelled - no transitions out.
"""
from __future__ import annotations

from datetime import datetime, timezone

VALID_TRANSITIONS: dict[str, tuple[str, ...]] = {
    # "failed" from queued/initializing is the startup-recovery path
    "queued": ("initializing", "cancelled", "failed"),
    "initializing": ("running", "cancelled", "failed"),
    "running": ("completed", "failed", "cancelling"),
    "cancelling": ("cancelled",),
    "completed": (),
    "failed": (),
    "cancelled": (),
}

TERMINAL_STATUSES = ("completed", "failed", "cancelled")
# Phase 2 cancellation is pure state management and only applies before
# execution exists; Phase 3 extends cancellation to running scans via
# the running -> cancelling transition.
CANCELLABLE_STATUSES = ("queued", "initializing")


class ScanStateError(Exception):
    """Invalid scan transition. The API layer translates to 409."""

    def __init__(self, current: str, target: str) -> None:
        super().__init__(f"Invalid scan transition: {current!r} -> {target!r}")
        self.current = current
        self.target = target


def can_transition(current: str, target: str) -> bool:
    return target in VALID_TRANSITIONS.get(current, ())


def apply_transition(
    scan,
    target: str,
    *,
    error: str | None = None,
    now: datetime | None = None,
) -> None:
    """Apply a validated transition to a Scan (ORM or duck-typed).

    Sets status plus the lifecycle timestamp the transition defines
    (started_at on ->initializing, completed_at on terminal, cancelled_at
    on ->cancelled, error on ->failed). Raises ScanStateError on invalid
    transitions.
    """
    current = scan.status
    if not can_transition(current, target):
        raise ScanStateError(current, target)
    ts = now or datetime.now(timezone.utc)
    scan.status = target
    if target == "initializing":
        scan.started_at = ts
    elif target in ("completed", "failed"):
        scan.completed_at = ts
        if target == "failed":
            scan.error = error
    elif target == "cancelled":
        scan.cancelled_at = ts
