"""Centralized API errors: codes, the ApiError exception, and handlers.

Every error response uses the envelope (see envelope.py). The code
vocabulary and HTTP status mapping are defined here. Internal stack
traces are never exposed to clients: 500 responses carry a generic
message and the traceback goes to the server log only.

Note: many policy/tool errors (out-of-scope target, tool timeout, ...)
are execution-time conditions that surface as tool-run statuses /
rejection observations rather than HTTP errors; their HTTP mappings are
assigned here for completeness.

Legacy /runs routes (removed in Phase 2) keep FastAPI's default
HTTPException handling; all v1 routes raise ApiError only.
"""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from backend.core.envelope import error_envelope

logger = logging.getLogger(__name__)


class ErrorCode:
    # resources
    PROJECT_NOT_FOUND = "PROJECT_NOT_FOUND"
    SCAN_NOT_FOUND = "SCAN_NOT_FOUND"
    FINDING_NOT_FOUND = "FINDING_NOT_FOUND"

    # targets / scope
    INVALID_TARGET = "INVALID_TARGET"
    TARGET_OUT_OF_SCOPE = "TARGET_OUT_OF_SCOPE"
    TARGET_NOT_AUTHORIZED = "TARGET_NOT_AUTHORIZED"

    # scan / agent input
    INVALID_SCAN_PROFILE = "INVALID_SCAN_PROFILE"
    INVALID_TOOL_PARAMETERS = "INVALID_TOOL_PARAMETERS"
    INVALID_AGENT_ACTION = "INVALID_AGENT_ACTION"

    # tools
    TOOL_NOT_ALLOWED = "TOOL_NOT_ALLOWED"
    INVALID_TOOL = "INVALID_TOOL"
    TOOL_TIMEOUT = "TOOL_TIMEOUT"
    TOOL_EXECUTION_FAILED = "TOOL_EXECUTION_FAILED"

    # scan lifecycle
    SCAN_ALREADY_RUNNING = "SCAN_ALREADY_RUNNING"
    SCAN_NOT_CANCELLABLE = "SCAN_NOT_CANCELLABLE"

    # auth
    EMAIL_ALREADY_REGISTERED = "EMAIL_ALREADY_REGISTERED"
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"

    # infrastructure
    DATABASE_ERROR = "DATABASE_ERROR"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"


_HTTP_STATUS: dict[str, int] = {
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


def http_status_for(code: str) -> int:
    return _HTTP_STATUS.get(code, 500)


class ApiError(Exception):
    """Domain error carrying a stable code.

    Raised by services/routers; rendered by the handlers registered in
    register_exception_handlers(). The executable truth is (code, message).
    """

    def __init__(self, code: str, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        # Optional explicit override (e.g. readiness must answer 503 with
        # DATABASE_ERROR while general database errors map to 500).
        self._status = status

    @property
    def http_status(self) -> int:
        if self._status is not None:
            return self._status
        return http_status_for(self.code)


def _envelope_response(
    request: Request, status: int, code: str, message: str
) -> JSONResponse:
    request_id = getattr(request.state, "request_id", "")
    body = error_envelope(code, message, request_id)
    return JSONResponse(status_code=status, content=body.model_dump(mode="json"))


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def handle_api_error(request: Request, exc: ApiError) -> JSONResponse:
        return _envelope_response(request, exc.http_status, exc.code, exc.message)

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return _envelope_response(
            request, 422, ErrorCode.VALIDATION_ERROR, "Request validation failed."
        )

    @app.exception_handler(SQLAlchemyError)
    async def handle_database_error(
        request: Request, exc: SQLAlchemyError
    ) -> JSONResponse:
        logger.exception("database error")
        return _envelope_response(
            request, 500, ErrorCode.DATABASE_ERROR, "A database error occurred."
        )

    @app.exception_handler(Exception)
    async def handle_unexpected(
        request: Request, exc: Exception
    ) -> JSONResponse:
        logger.exception("unhandled exception")
        return _envelope_response(
            request, 500, ErrorCode.INTERNAL_ERROR, "An internal error occurred."
        )
