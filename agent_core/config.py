"""Environment-driven configuration (pydantic-settings).

No credentials are required for the foundation.  All variables are
prefixed with ``AICYBERSEC_`` and all have safe defaults.

    AICYBERSEC_RUNS_DIR=runs              where state/trajectory files go
    AICYBERSEC_ALLOWED_TARGETS=a,b,c      default allowlist (comma-separated)
    AICYBERSEC_MAX_DANGER=active_scan     policy cap: safe|active_scan|intrusive
    AICYBERSEC_DEFAULT_MODE=recon         run mode string
    AICYBERSEC_MAX_STEPS=12               step budget per run
    AICYBERSEC_TOOL_TIMEOUT_S=60          per-tool timeout
"""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AICYBERSEC_", env_file=".env", extra="ignore"
    )

    runs_dir: str = "runs"
    allowed_targets: str = ""
    max_danger: str = "active_scan"
    default_mode: str = "recon"
    max_steps: int = 12
    tool_timeout_s: int = 60

    def allowed_targets_list(self) -> list[str]:
        return [t.strip() for t in self.allowed_targets.split(",") if t.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
