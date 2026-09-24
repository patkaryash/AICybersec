"""Scan service: contract-level lifecycle (Phase 2 - NO execution).

Phase 2 semantics: POST /scans authenticates, authorizes the project,
validates configuration, copies the project scope into target_snapshot
(the authorization anchor), persists the record with status="queued"
and returns it. NO execution is scheduled - no thread, no asyncio task,
no subprocess, no tool, no ScanManager, no AI call. Phase 3 adds the
ScanManager/background pipeline. Cancel is pure state management via
backend/services/scan_state.py.
"""
from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.core.errors import ApiError, ErrorCode
from backend.db.models import Finding, Project, Scan, User
from backend.schemas.scans import (
    CANCELLABLE_STATUSES,
    PROFILE_TOTAL_STEPS,
    FindingsCount,
    ScanCreate,
    ScanOut,
)
from backend.services.project_service import get_project_for_user
from backend.services.scan_state import apply_transition


def get_scan_for_user(session: Session, scan_id: uuid.UUID, user: User) -> Scan:
    """Ownership gate for scans: 404 SCAN_NOT_FOUND when missing or not
    owned (access via scan -> project -> owner_id; admins bypass).
    Consistent 404 prevents resource enumeration."""
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise ApiError(ErrorCode.SCAN_NOT_FOUND, "Scan does not exist.")
    project = session.get(Project, scan.project_id)
    if user.role != "admin" and (project is None or project.owner_id != user.id):
        raise ApiError(ErrorCode.SCAN_NOT_FOUND, "Scan does not exist.")
    return scan


def scan_out(scan: Scan, severity_counts: dict[str, int] | None = None) -> ScanOut:
    """ORM row -> ScanOut. current_step is 0 in Phase 2 (no execution)."""
    per_sev = severity_counts or {}
    return ScanOut(
        id=scan.id,
        project_id=scan.project_id,
        status=scan.status,
        mode=scan.mode,
        profile=scan.profile,
        goal=scan.goal,
        target_snapshot=list(scan.target_snapshot or []),
        tool_timeout_s=scan.tool_timeout_s,
        error=scan.error,
        created_at=scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        cancelled_at=scan.cancelled_at,
        updated_at=scan.updated_at,
        total_steps=PROFILE_TOTAL_STEPS.get(scan.profile, 3),
        current_step=0,
        findings_count=FindingsCount(
            critical=per_sev.get("critical", 0),
            high=per_sev.get("high", 0),
            medium=per_sev.get("medium", 0),
            low=per_sev.get("low", 0),
            info=per_sev.get("info", 0),
            total=sum(per_sev.values()),
        ),
    )


def findings_counts_by_scan(
    session: Session, scan_ids: list[uuid.UUID]
) -> dict[uuid.UUID, dict[str, int]]:
    """ONE aggregate query: findings count by severity per scan (no N+1)."""
    if not scan_ids:
        return {}
    rows = session.execute(
        select(Finding.scan_id, Finding.scanner_severity, func.count())
        .where(Finding.scan_id.in_(scan_ids))
        .group_by(Finding.scan_id, Finding.scanner_severity)
    ).all()
    out: dict[uuid.UUID, dict[str, int]] = {}
    severities = ("critical", "high", "medium", "low", "info")
    for scan_id, severity, count in rows:
        counts = out.setdefault(scan_id, {s: 0 for s in severities})
        counts[severity] = int(count)
    return out


def create_scan(session: Session, *, user: User, data: ScanCreate) -> Scan:
    """Create + persist the queued scan (Phase 2: nothing is scheduled).

    The partial unique index (uq_scans_project_active) is the DB-level
    guarantee: a second active scan on the project raises IntegrityError,
    translated to 409 SCAN_ALREADY_RUNNING without leaking PostgreSQL
    error text.
    """
    project = get_project_for_user(session, data.project_id, user)
    scan = Scan(
        project_id=project.id,
        status="queued",
        mode=data.mode,
        profile=data.profile,
        goal=data.goal,
        target_snapshot=list(project.scope or []),
        max_steps=data.max_steps,
        tool_timeout_s=data.tool_timeout_s,
    )
    session.add(scan)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise ApiError(
            ErrorCode.SCAN_ALREADY_RUNNING, "Project already has an active scan."
        ) from None
    session.refresh(scan)
    return scan


def list_scans(
    session: Session,
    *,
    user: User,
    page: int,
    page_size: int,
    project_id: uuid.UUID | None = None,
    status: str | None = None,
) -> tuple[list[Scan], int]:
    """Scans visible to the user (ownership always applies), newest first.

    An explicit project_id that is invisible to the user -> 404
    PROJECT_NOT_FOUND (consistent with the detail endpoint).
    """
    query = select(Scan).join(Project, Scan.project_id == Project.id)
    if user.role != "admin":
        query = query.where(Project.owner_id == user.id)
    if project_id is not None:
        get_project_for_user(session, project_id, user)  # 404 when invisible
        query = query.where(Scan.project_id == project_id)
    if status is not None:
        query = query.where(Scan.status == status)
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = (
        session.scalars(
            query.order_by(Scan.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        .all()
    )
    return list(rows), total


def cancel_scan(session: Session, *, user: User, scan_id: uuid.UUID) -> Scan:
    """Phase 2 cancellation: pure state management.

    queued/initializing -> cancelled (direct); any other state ->
    409 SCAN_NOT_CANCELLABLE. No process termination (Phase 3).
    """
    scan = get_scan_for_user(session, scan_id, user)
    if scan.status not in CANCELLABLE_STATUSES:
        raise ApiError(ErrorCode.SCAN_NOT_CANCELLABLE, "Scan is not cancellable.")
    apply_transition(scan, "cancelled")
    session.commit()
    session.refresh(scan)
    return scan
