"""Finding service: read-only, scan-scoped, ownership via scan -> project."""
from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.core.errors import ApiError, ErrorCode
from backend.db.models import Finding, User
from backend.services.scan_service import get_scan_for_user


def get_finding_for_user(
    session: Session, finding_id: uuid.UUID, user: User
) -> Finding:
    """404 FINDING_NOT_FOUND when missing or not owned (access via
    finding -> scan -> project -> owner_id). Consistent 404 prevents
    resource enumeration."""
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise ApiError(ErrorCode.FINDING_NOT_FOUND, "Finding does not exist.")
    get_scan_for_user(session, finding.scan_id, user)  # ownership gate (404)
    return finding


def list_findings_for_scan(
    session: Session,
    *,
    user: User,
    scan_id: uuid.UUID,
    page: int,
    page_size: int,
    severity: str | None = None,
    status: str | None = None,
) -> tuple[list[Finding], int]:
    """Findings for one visible scan, newest first (404 when invisible)."""
    get_scan_for_user(session, scan_id, user)
    query = select(Finding).where(Finding.scan_id == scan_id)
    if severity is not None:
        query = query.where(Finding.scanner_severity == severity)
    if status is not None:
        query = query.where(Finding.status == status)
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = (
        session.scalars(
            query.order_by(Finding.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        .all()
    )
    return list(rows), total
