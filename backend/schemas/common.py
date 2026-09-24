"""Shared API DTOs: pagination parameters (page >= 1, page_size 1..100)."""
from __future__ import annotations

from pydantic import BaseModel, Field


class PaginationParams(BaseModel):
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)
