"""FastAPI application factory for the AICybersec backend.

Platform backend: /api/v1 routers, envelope + error handlers, CORS,
request-id middleware, and a lifespan that seeds the default admin user.
Startup recovery of stale scans lands with the ScanManager (Phase 3).

Legacy routes kept temporarily (deliberate migration in Phase 2):
- GET /health and the /runs router (removed together with the legacy
  contract when /api/v1 fully replaces them).
"""
from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from backend.api import health
from backend.core.config import get_backend_settings
from backend.core.errors import register_exception_handlers
from backend.routes import runs

logger = logging.getLogger(__name__)


def _seed_admin() -> None:
    """Create the default admin user if missing (lab convenience).

    Driven by AICYBERSEC_ADMIN_EMAIL / AICYBERSEC_ADMIN_PASSWORD. The
    password is hashed (Argon2id) and never logged or returned.
    """
    from sqlalchemy import select

    from backend.core.passwords import hash_password
    from backend.db.models import User
    from backend.db.session import get_session_factory

    settings = get_backend_settings()
    if not settings.admin_email or not settings.admin_password:
        return
    with get_session_factory().begin() as session:
        existing = session.scalar(
            select(User).where(User.email == settings.admin_email.lower())
        )
        if existing is not None:
            return
        session.add(
            User(
                email=settings.admin_email.lower(),
                password_hash=hash_password(settings.admin_password),
                role="admin",
            )
        )
    logger.info("seeded default admin user")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # The database may be unavailable (offline tests, first boot before
    # postgres is up) - never block startup on it.
    try:
        _seed_admin()
    except Exception:
        logger.warning("database unavailable; skipping admin seed")
    yield


def create_app() -> FastAPI:
    settings = get_backend_settings()
    app = FastAPI(
        title="AICybersec backend",
        version="0.1.0",
        description=(
            "AI-assisted pentesting platform - orchestration, policy, "
            "persistence, and execution control. Authorized lab targets only."
        ),
        docs_url="/api/v1/docs",
        redoc_url="/api/v1/redoc",
        openapi_url="/api/v1/openapi.json",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list(),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        request.state.request_id = str(uuid.uuid4())
        return await call_next(request)

    register_exception_handlers(app)
    app.include_router(health.router)
    app.include_router(runs.router)  # legacy /runs API - removed in Phase 2

    @app.get("/health", include_in_schema=False)
    def legacy_health() -> dict:
        return {"status": "ok"}

    return app


app = create_app()
