"""Response envelope: the single response shape for every API response.

Success:
    {"success": true, "data": ..., "error": null, "meta": {"request_id": ...}}
Error:
    {"success": false, "data": null,
     "error": {"code": "...", "message": "..."}, "meta": {"request_id": ...}}
Paginated:
    data is {"items": [...]} and meta additionally carries page/page_size/total.

Routers must not hand-build envelopes; use the helpers here. Maximum page
size is 100. Timestamps in payloads are UTC ISO-8601.
"""
from __future__ import annotations

from typing import Generic, Sequence, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")

DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 100


class ErrorBody(BaseModel):
    code: str
    message: str


class Meta(BaseModel):
    request_id: str
    page: int | None = Field(default=None, ge=1)
    page_size: int | None = Field(default=None, ge=1)
    total: int | None = Field(default=None, ge=0)


class Envelope(BaseModel, Generic[T]):
    success: bool = True
    data: T | None = None
    error: ErrorBody | None = None
    meta: Meta


class PageData(BaseModel, Generic[T]):
    """Paginated payload: data.items."""

    items: list[T] = Field(default_factory=list)


def normalize_pagination(page: int, page_size: int) -> tuple[int, int]:
    """Clamp pagination to safe bounds (page >= 1, 1 <= page_size <= 100)."""
    return max(1, page), min(max(1, page_size), MAX_PAGE_SIZE)


def ok(data: T, request_id: str) -> Envelope[T]:
    return Envelope[T](success=True, data=data, meta=Meta(request_id=request_id))


def paginated(
    items: Sequence[T],
    page: int,
    page_size: int,
    total: int,
    request_id: str,
) -> Envelope[PageData[T]]:
    page, page_size = normalize_pagination(page, page_size)
    return Envelope[PageData[T]](
        success=True,
        data=PageData[T](items=list(items)),
        meta=Meta(
            request_id=request_id, page=page, page_size=page_size, total=total
        ),
    )


def error_envelope(code: str, message: str, request_id: str) -> Envelope[None]:
    return Envelope[None](
        success=False,
        error=ErrorBody(code=code, message=message),
        meta=Meta(request_id=request_id),
    )
