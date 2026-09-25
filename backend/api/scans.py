"""Scans API: thin routers over backend/services/scan_service.py.

Phase 3: creation persists a queued record, returns 202, and submits
the scan to the ScanManager for background execution (unless disabled
via AICYBERSEC_SCAN_AUTO_START=0). The request never waits for the run.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from backend.api.deps import get_current_user
from backend.core.envelope import Envelope, PageData, ok, paginated
from backend.db.models import User
from backend.db.session import get_db
from backend.schemas.scans import ScanCreate, ScanOut, ScanStatus
from backend.services import scan_service
from backend.services.scan_manager import get_scan_manager

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "")


@router.post("", response_model=Envelope[ScanOut], status_code=202)
def create_scan(
    body: ScanCreate,
    request: Request,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> Envelope[ScanOut]:
    from backend.core.config import get_backend_settings

    scan = scan_service.create_scan(session, user=user, data=body)
    if get_backend_settings().scan_auto_start:
        get_scan_manager().submit(scan.id)
        session.refresh(scan)
    return ok(scan_service.scan_out(scan), _request_id(request))


@router.get("", response_model=Envelope[PageData[ScanOut]])
def list_scans(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    project_id: uuid.UUID | None = Query(default=None),
    status: ScanStatus | None = Query(default=None),
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> Envelope[PageData[ScanOut]]:
    rows, total = scan_service.list_scans(
        session,
        user=user,
        page=page,
        page_size=page_size,
        project_id=project_id,
        status=status,
    )
    counts = scan_service.findings_counts_by_scan(session, [s.id for s in rows])
    return paginated(
        [scan_service.scan_out(s, counts.get(s.id)) for s in rows],
        page,
        page_size,
        total,
        _request_id(request),
    )


@router.get("/{scan_id}", response_model=Envelope[ScanOut])
def get_scan(
    scan_id: uuid.UUID,
    request: Request,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> Envelope[ScanOut]:
    scan = scan_service.get_scan_for_user(session, scan_id, user)
    counts = scan_service.findings_counts_by_scan(session, [scan.id])
    return ok(scan_service.scan_out(scan, counts.get(scan.id)), _request_id(request))


@router.post("/{scan_id}/cancel", response_model=Envelope[ScanOut], status_code=202)
def cancel_scan(
    scan_id: uuid.UUID,
    request: Request,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> Envelope[ScanOut]:
    scan = scan_service.cancel_scan(session, user=user, scan_id=scan_id)
    return ok(scan_service.scan_out(scan), _request_id(request))
