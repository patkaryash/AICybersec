"""Live authorizations API (Phase 5 Stage 1).

Thin routers over backend/services/live_authorization_service.py.
Activation (create), suspend and revoke are ADMIN-ONLY; reads apply
project-visibility with consistent 404 anti-enumeration. There is NO
update/resume endpoint: records are immutable and suspension is
one-way in v1 (a new authorization must be issued).
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from backend.api.deps import get_current_user
from backend.core.envelope import Envelope, PageData, ok, paginated
from backend.schemas.live_authorization import (
    LiveAuthorizationCreate,
    LiveAuthorizationOut,
    LiveAuthorizationOwnerOut,
)
from backend.db.models import LiveAuthorization, User
from backend.db.session import get_db
from backend.services import live_authorization_service as live_service

router = APIRouter(prefix="/api/v1/live-authorizations", tags=["live-authorizations"])

# F6: reads are role-dependent, so the declared response model is the
# union; FastAPI serializes against whichever member the handler built.
AuthorizationRead = LiveAuthorizationOut | LiveAuthorizationOwnerOut


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "")


def _out(
    auth: LiveAuthorization, user: User
) -> LiveAuthorizationOut | LiveAuthorizationOwnerOut:
    """F6 role-based response minimization: admins receive the full
    audit DTO (evidence + approver); non-admins receive the owner DTO
    that excludes evidence/approver metadata. Lifecycle/access is
    unchanged: admins see all detail on their own projects."""
    if user.role == "admin":
        return LiveAuthorizationOut.model_validate(auth, from_attributes=True)
    return LiveAuthorizationOwnerOut.model_validate(auth, from_attributes=True)


@router.post("", response_model=Envelope[LiveAuthorizationOut], status_code=201)
def create_live_authorization(
    body: LiveAuthorizationCreate,
    request: Request,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> Envelope[LiveAuthorizationOut]:
    auth = live_service.create_live_authorization(session, user=user, data=body)
    return ok(_out(auth, user), _request_id(request))


@router.get("", response_model=Envelope[PageData[AuthorizationRead]])
def list_live_authorizations(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    project_id: uuid.UUID | None = Query(default=None),
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> Envelope[PageData[LiveAuthorizationOut]]:
    rows, total = live_service.list_live_authorizations(
        session,
        user=user,
        page=page,
        page_size=page_size,
        project_id=project_id,
    )
    return paginated(
        [_out(a, user) for a in rows], page, page_size, total, _request_id(request)
    )


@router.get("/{authorization_id}", response_model=Envelope[AuthorizationRead])
def get_live_authorization(
    authorization_id: uuid.UUID,
    request: Request,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> Envelope[AuthorizationRead]:
    auth = live_service.get_live_authorization_for_user(session, authorization_id, user)
    return ok(_out(auth, user), _request_id(request))


@router.post(
    "/{authorization_id}/suspend", response_model=Envelope[LiveAuthorizationOut]
)
def suspend_live_authorization(
    authorization_id: uuid.UUID,
    request: Request,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> Envelope[LiveAuthorizationOut]:
    auth = live_service.suspend_live_authorization(
        session, user=user, authorization_id=authorization_id
    )
    return ok(_out(auth, user), _request_id(request))


@router.post(
    "/{authorization_id}/revoke", response_model=Envelope[LiveAuthorizationOut]
)
def revoke_live_authorization(
    authorization_id: uuid.UUID,
    request: Request,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> Envelope[LiveAuthorizationOut]:
    auth = live_service.revoke_live_authorization(
        session, user=user, authorization_id=authorization_id
    )
    return ok(_out(auth, user), _request_id(request))
