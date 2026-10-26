"""Backend configuration (pydantic-settings).

Separate from agent_core.config: this object owns platform concerns
(database, auth, CORS, limits, AI provider). All variables use the
AICYBERSEC_ prefix and share the .env file. Dev defaults are safe for
local/lab use only and are documented in .env.example; never provide
production secrets.
"""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

DEV_INSECURE_JWT_SECRET = "dev-insecure-jwt-secret-change-me"


class BackendSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AICYBERSEC_", env_file=".env", extra="ignore"
    )

    # --- Database (PostgreSQL + psycopg 3 driver) ---
    # 127.0.0.1 rather than localhost: avoids IPv6-first double connection
    # attempts on Windows dev machines (relevant when no server is running).
    database_url: str = (
        "postgresql+psycopg://aicybersec:aicybersec@127.0.0.1:5432/aicybersec"
    )

    # --- Auth / JWT ---
    jwt_secret: str = DEV_INSECURE_JWT_SECRET
    jwt_expiry_s: int = 86400
    admin_email: str = "admin@aicybersec.dev"
    admin_password: str = "admin-dev-password-change-me"

    # --- CORS (comma-separated allowed origins; never "*" with credentials) ---
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    # --- Limits ---
    max_concurrent_scans: int = 2
    default_tool_timeout_s: int = 300
    max_tool_output_bytes: int = 524_288  # 512 KB

    # --- Scan execution (Phase 3) ---
    # AICYBERSEC_SCAN_AUTO_START: whether POST /scans submits the scan
    # to the ScanManager immediately. Default True (production behavior);
    # tests set 0 for determinism.
    scan_auto_start: bool = True

    # --- Phase 5: live website assessment (opt-in, DEFAULT OFF) ---
    # Stage 1 ships authorization records + immutable snapshots ONLY.
    # No live HTTP execution exists in Stage 1 regardless of this flag:
    # the ScanManager hard-refuses live_probe scans (defense in depth).
    live_probe_enabled: bool = False
    # Policy version stamped onto authorizations and snapshots; bumping
    # it invalidates every existing live authorization (fail closed).
    live_probe_policy_version: str = "live-probe/v1"
    # Maximum authorization lifetime in days (validated at creation;
    # stricter windows are always allowed).
    live_probe_max_authorization_days: int = 90

    # --- Runtime artifacts (agent state, trajectory, raw tool output) ---
    runs_dir: str = "runs"

    # --- AI provider (Phase 8; no external LLM is needed before then) ---
    provider: str = "mock"
    ai_base_url: str = ""
    ai_model: str = ""
    ai_api_key: str = ""

    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_backend_settings() -> BackendSettings:
    return BackendSettings()
