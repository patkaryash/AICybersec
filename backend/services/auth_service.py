"""Authentication service: registration and login.

Passwords are hashed with the existing Argon2id infrastructure
(backend.core.passwords) and never logged. Authentication failures are
always the same generic 401 INVALID_CREDENTIALS - unknown user, wrong
password and deactivated user are indistinguishable (no account-state
disclosure).
"""
from __future__ import annotations

from functools import lru_cache

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.core.errors import ApiError, ErrorCode
from backend.core.passwords import hash_password, verify_password
from backend.db.models import User


def normalize_email(email: str) -> str:
    return email.strip().lower()


def get_user_by_email(session: Session, email: str) -> User | None:
    return session.scalar(select(User).where(User.email == normalize_email(email)))


@lru_cache
def _dummy_hash() -> str:
    """Constant dummy hash for timing equalization (see authenticate_user)."""
    return hash_password("timing-equalizer-dummy-account")


def register_user(
    session: Session,
    *,
    email: str,
    password: str,
    display_name: str | None = None,
) -> User:
    """Create a user with role="user" (role is never client-controlled;
    admin accounts exist only via the startup seed).

    Duplicate detection covers both the application-level pre-check and
    the PostgreSQL unique-index race; both translate to
    409 EMAIL_ALREADY_REGISTERED without leaking database internals.
    """
    normalized = normalize_email(email)
    if get_user_by_email(session, normalized) is not None:
        raise ApiError(ErrorCode.EMAIL_ALREADY_REGISTERED, "Email is already registered.")
    user = User(
        email=normalized,
        password_hash=hash_password(password),
        display_name=display_name,
        role="user",
    )
    session.add(user)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise ApiError(ErrorCode.EMAIL_ALREADY_REGISTERED, "Email is already registered.") from None
    session.refresh(user)
    return user


def authenticate_user(session: Session, *, email: str, password: str) -> User:
    """Verify credentials and return the user.

    Unknown user / wrong password / deactivated user all raise the same
    generic 401 INVALID_CREDENTIALS. For unknown users the password is
    still verified against a constant dummy hash to equalize response
    timing (timing-based account enumeration mitigation).
    """
    user = get_user_by_email(session, email)
    if user is None:
        verify_password(password, _dummy_hash())
        raise ApiError(ErrorCode.INVALID_CREDENTIALS, "Invalid email or password.")
    if not user.is_active or not verify_password(password, user.password_hash):
        raise ApiError(ErrorCode.INVALID_CREDENTIALS, "Invalid email or password.")
    return user
