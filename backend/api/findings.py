"""Findings API: thin routers over backend/services/finding_service.py."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from backend.api.deps import get_current_user
from backend.core.envelope import Envelope, PageData, ok, paginated
from backend.db.models import Finding, User
from backend.db.session import get_db
from backend.schemas.findings import FindingOut, FindingStatus, Severity
from backend.services import finding_service

router = APIRouter(prefix="/api/v1", tags=["findings"])


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "")


def _finding_out(finding: Finding) -> FindingOut:
    return FindingOut.model_validate(finding, from_attributes=True)


@router.get("/scans/{scan_id}/findings", response_model=Envelope[PageData[FindingOut]])
def list_findings(
    scan_id: uuid.UUID,
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    severity: Severity | None = Query(default=None),
    status: FindingStatus | None = Query(default=None),
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> Envelope[PageData[FindingOut]]:
    rows, total = finding_service.list_findings_for_scan(
        session,
        user=user,
        scan_id=scan_id,
        page=page,
        page_size=page_size,
        severity=severity,
        status=status,
    )
    return paginated(
        [_finding_out(f) for f in rows], page, page_size, total, _request_id(request)
    )


@router.get("/findings/{finding_id}", response_model=Envelope[FindingOut])
def get_finding(
    finding_id: uuid.UUID,
    request: Request,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> Envelope[FindingOut]:
    finding = finding_service.get_finding_for_user(session, finding_id, user)
    return ok(_finding_out(finding), _request_id(request))
