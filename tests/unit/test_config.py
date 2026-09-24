"""Unit tests: backend settings defaults and env overrides."""
from __future__ import annotations

import pytest

from backend.core.config import BackendSettings, get_backend_settings

_AICYBERSEC_VARS = (
    "AICYBERSEC_DATABASE_URL",
    "AICYBERSEC_JWT_SECRET",
    "AICYBERSEC_JWT_EXPIRY_S",
    "AICYBERSEC_ADMIN_EMAIL",
    "AICYBERSEC_ADMIN_PASSWORD",
    "AICYBERSEC_CORS_ORIGINS",
    "AICYBERSEC_MAX_CONCURRENT_SCANS",
    "AICYBERSEC_DEFAULT_TOOL_TIMEOUT_S",
    "AICYBERSEC_MAX_TOOL_OUTPUT_BYTES",
    "AICYBERSEC_RUNS_DIR",
    "AICYBERSEC_PROVIDER",
    "AICYBERSEC_AI_BASE_URL",
    "AICYBERSEC_AI_MODEL",
    "AICYBERSEC_AI_API_KEY",
)


@pytest.fixture()
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _AICYBERSEC_VARS:
        monkeypatch.delenv(var, raising=False)


def test_defaults(clean_env):
    s = BackendSettings()
    assert s.database_url.startswith("postgresql+psycopg://")
    assert s.max_concurrent_scans == 2
    assert s.default_tool_timeout_s == 300
    assert s.max_tool_output_bytes == 524_288
    assert s.jwt_expiry_s == 86400
    assert s.provider == "mock"
    assert s.runs_dir == "runs"


def test_env_override(clean_env, monkeypatch):
    monkeypatch.setenv(
        "AICYBERSEC_DATABASE_URL", "postgresql+psycopg://x:y@localhost:1/z"
    )
    monkeypatch.setenv("AICYBERSEC_MAX_CONCURRENT_SCANS", "5")
    monkeypatch.setenv("AICYBERSEC_CORS_ORIGINS", "http://a.test, http://b.test")
    s = BackendSettings()
    assert s.database_url == "postgresql+psycopg://x:y@localhost:1/z"
    assert s.max_concurrent_scans == 5
    assert s.cors_origins_list() == ["http://a.test", "http://b.test"]


def test_cached_settings_reset(clean_env):
    s1 = get_backend_settings()
    get_backend_settings.cache_clear()
    s2 = get_backend_settings()
    assert s1 is not s2
