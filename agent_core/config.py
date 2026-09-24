"""Environment-driven configuration (pydantic-settings).

No credentials are required for the foundation.  All variables are
prefixed with ``AICYBERSEC_`` and all have safe defaults.

    AICYBERSEC_RUNS_DIR=runs              where state/trajectory files go
    AICYBERSEC_ALLOWED_TARGETS=a,b,c      default allowlist (comma-separated)
    AICYBERSEC_MAX_DANGER=active_scan     policy cap: safe|active_scan|intrusive
    AICYBERSEC_DEFAULT_MODE=recon         run mode string
    AICYBERSEC_MAX_STEPS=12               step budget per run
    AICYBERSEC_TOOL_TIMEOUT_S=60          per-tool timeout

Model selection (M3-C; inert by default):

    AICYBERSEC_MODEL_PROVIDER=mock        mock | openai_compatible
    AICYBERSEC_MODEL_BASE_URL=            e.g. http://localhost:11434/v1
    AICYBERSEC_MODEL_API_KEY=             bearer token (empty for local servers)
    AICYBERSEC_MODEL_NAME=                model id sent to the endpoint
    AICYBERSEC_MODEL_TIMEOUT_S=60         per-request timeout
    AICYBERSEC_MODEL_MAX_RESPONSE_CHARS=8000  raw completion cap

Names are deliberately MODEL_*-prefixed so they never collide with the
backend team's Phase 2/8 AI_* settings. Never commit real keys.
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
    # Model selection (M3-C). Defaults keep every existing path on
    # mock/scripted behavior; a real endpoint is strictly opt-in.
    model_provider: str = "mock"
    model_base_url: str = ""
    model_api_key: str = ""
    model_name: str = ""
    model_timeout_s: int = 60
    model_max_response_chars: int = 8000

    def allowed_targets_list(self) -> list[str]:
        return [t.strip() for t in self.allowed_targets.split(",") if t.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
