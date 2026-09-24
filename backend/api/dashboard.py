"""Dashboard API: the single coherent dashboard endpoint."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from backend.api.deps import get_current_user
from backend.core.envelope import Envelope, ok
from backend.db.models import User
from backend.db.session import get_db
from backend.schemas.scans import DashboardOut
from backend.services import dashboard_service

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("", response_model=Envelope[DashboardOut])
def dashboard(
    request: Request,
    recent_limit: int = Query(default=6, ge=1, le=50),
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> Envelope[DashboardOut]:
    data = dashboard_service.dashboard_data(session, user=user, recent_limit=recent_limit)
    return ok(
        DashboardOut(**data),
        request_id=getattr(request.state, "request_id", ""),
    )
