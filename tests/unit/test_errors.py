"""Unit tests: error codes, HTTP status mapping, ApiError."""
from __future__ import annotations

import pytest

from backend.core.errors import ApiError, ErrorCode, http_status_for

EXPECTED: dict[str, int] = {
    ErrorCode.PROJECT_NOT_FOUND: 404,
    ErrorCode.SCAN_NOT_FOUND: 404,
    ErrorCode.FINDING_NOT_FOUND: 404,
    ErrorCode.INVALID_TARGET: 422,
    ErrorCode.TARGET_OUT_OF_SCOPE: 403,
    ErrorCode.TARGET_NOT_AUTHORIZED: 403,
    ErrorCode.INVALID_SCAN_PROFILE: 422,
    ErrorCode.INVALID_TOOL_PARAMETERS: 422,
    ErrorCode.INVALID_AGENT_ACTION: 400,
    ErrorCode.TOOL_NOT_ALLOWED: 403,
    ErrorCode.INVALID_TOOL: 422,
    ErrorCode.TOOL_TIMEOUT: 504,
    ErrorCode.TOOL_EXECUTION_FAILED: 500,
    ErrorCode.SCAN_ALREADY_RUNNING: 409,
    ErrorCode.SCAN_NOT_CANCELLABLE: 409,
    ErrorCode.EMAIL_ALREADY_REGISTERED: 409,
    ErrorCode.INVALID_CREDENTIALS: 401,
    ErrorCode.DATABASE_ERROR: 500,
    ErrorCode.VALIDATION_ERROR: 422,
    ErrorCode.INTERNAL_ERROR: 500,
}


def test_all_error_codes_mapped():
    assert len(EXPECTED) == 20
    for code, status in EXPECTED.items():
        assert http_status_for(code) == status


def test_unknown_code_defaults_to_500():
    assert http_status_for("NOPE") == 500


def test_explicit_status_override():
    """Readiness answers 503 with DATABASE_ERROR; general DB errors are 500."""
    assert ApiError(ErrorCode.DATABASE_ERROR, "msg").http_status == 500
    assert (
        ApiError(ErrorCode.DATABASE_ERROR, "msg", status=503).http_status == 503
    )


@pytest.mark.parametrize(("code", "status"), sorted(EXPECTED.items()))
def test_api_error_carries_status(code: str, status: int):
    err = ApiError(code, "msg")
    assert err.code == code
    assert err.message == "msg"
    assert err.http_status == status
