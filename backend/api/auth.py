"""Auth API: register, login, me.

Thin routers: parse, authenticate, call the service, return the typed
envelope. Business rules live in backend/services/auth_service.py.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from backend.api.deps import get_current_user
from backend.core.config import get_backend_settings
from backend.core.envelope import Envelope, ok
from backend.core.jwt import create_access_token
from backend.db.models import User
from backend.db.session import get_db
from backend.schemas.auth import LoginRequest, RegisterRequest, TokenResponse, UserOut
from backend.services import auth_service

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "")


def _user_out(user: User) -> UserOut:
    return UserOut.model_validate(user, from_attributes=True)


@router.post("/register", response_model=Envelope[UserOut], status_code=201)
def register(
    body: RegisterRequest,
    request: Request,
    session: Session = Depends(get_db),
) -> Envelope[UserOut]:
    user = auth_service.register_user(
        session,
        email=body.email,
        password=body.password,
        display_name=body.display_name,
    )
    return ok(_user_out(user), request_id=_request_id(request))


@router.post("/login", response_model=Envelope[TokenResponse])
def login(
    body: LoginRequest,
    request: Request,
    session: Session = Depends(get_db),
) -> Envelope[TokenResponse]:
    user = auth_service.authenticate_user(
        session, email=body.email, password=body.password
    )
    settings = get_backend_settings()
    return ok(
        TokenResponse(
            access_token=create_access_token(str(user.id)),
            expires_in=settings.jwt_expiry_s,
        ),
        request_id=_request_id(request),
    )


@router.get("/me", response_model=Envelope[UserOut])
def me(
    request: Request,
    user: User = Depends(get_current_user),
) -> Envelope[UserOut]:
    return ok(_user_out(user), request_id=_request_id(request))
