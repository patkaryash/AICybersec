"""FastAPI dependencies: authentication.

get_current_user resolves the authenticated user from the Authorization
header (HTTPBearer + JWT + database lookup). The database lookup is
intentional: role/is_active are authoritative in the DB and never
trusted from JWT claims.
"""
from __future__ import annotations

import uuid

from fastapi import Depends, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from backend.core.errors import ApiError, ErrorCode
from backend.core.jwt import decode_access_token
from backend.db.models import User
from backend.db.session import get_db

_bearer = HTTPBearer(auto_error=False, description="JWT access token")


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
    session: Session = Depends(get_db),
) -> User:
    """Resolve the authenticated user.

    Missing/invalid/expired/forged tokens and missing/deactivated users
    all raise the same 401 INVALID_CREDENTIALS (no state disclosure).
    """
    if credentials is None or not credentials.credentials:
        raise ApiError(ErrorCode.INVALID_CREDENTIALS, "Authentication required.")
    payload = decode_access_token(credentials.credentials)
    sub = payload.get("sub") if payload else None
    if not sub:
        raise ApiError(ErrorCode.INVALID_CREDENTIALS, "Invalid or expired token.")
    try:
        user_id = uuid.UUID(str(sub))
    except ValueError:
        raise ApiError(ErrorCode.INVALID_CREDENTIALS, "Invalid or expired token.") from None
    user = session.get(User, user_id)
    if user is None or not user.is_active:
        raise ApiError(ErrorCode.INVALID_CREDENTIALS, "Invalid or expired token.")
    return user
