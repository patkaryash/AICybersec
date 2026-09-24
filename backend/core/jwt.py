"""JWT helpers: HS256 access tokens via PyJWT.

Pure functions, unit-testable, not coupled to FastAPI. The payload
contains exactly sub/iat/exp - no role, no jti, no token-type claim:
the current user's database record is fetched on every authenticated
request, so role/is_active remain authoritative in the DB.

The secret comes from AICYBERSEC_JWT_SECRET and must never be logged or
returned by any endpoint.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import jwt

from backend.core.config import get_backend_settings

ALGORITHM = "HS256"


def create_access_token(user_id: str, expires_in_s: int | None = None) -> str:
    """Create an HS256 access token for the given user id."""
    settings = get_backend_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "iat": int(now.timestamp()),
        "exp": int(
            (now + timedelta(seconds=expires_in_s or settings.jwt_expiry_s)).timestamp()
        ),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any] | None:
    """Decode and verify an access token.

    Returns None on ANY failure (malformed, tampered signature, wrong
    secret, expired, or missing required claims). Callers translate None
    into 401 INVALID_CREDENTIALS - never a more specific disclosure.
    """
    try:
        return jwt.decode(
            token,
            get_backend_settings().jwt_secret,
            algorithms=[ALGORITHM],
            options={"require": ["sub", "exp", "iat"]},
        )
    except jwt.PyJWTError:
        return None
