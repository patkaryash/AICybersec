"""FastAPI application factory for the AICybersec backend."""
from __future__ import annotations

from fastapi import FastAPI

from backend.routes import runs


def create_app() -> FastAPI:
    app = FastAPI(
        title="AICybersec backend",
        version="0.1.0",
        description="Thin HTTP adapter over agent_core (in-process, mock-first).",
    )
    app.include_router(runs.router)

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    return app


app = create_app()
