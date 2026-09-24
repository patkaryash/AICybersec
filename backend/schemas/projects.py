"""Project DTOs.

Scope entries are validated and normalized by the scope service before
persistence; the canonical form is what gets stored and returned.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

ScopeType = Literal["host", "cidr", "url"]
ProjectStatus = Literal["active", "archived"]


class ScopeEntry(BaseModel):
    type: ScopeType
    value: str = Field(min_length=1, max_length=500)
    note: str | None = Field(default=None, max_length=300)


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    description: str | None = Field(default=None, max_length=2000)
    scope: list[ScopeEntry] = Field(min_length=1)


class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=150)
    description: str | None = Field(default=None, max_length=2000)
    scope: list[ScopeEntry] | None = Field(default=None, min_length=1)
    status: ProjectStatus | None = None


class ProjectOut(BaseModel):
    id: uuid.UUID
    owner_id: uuid.UUID
    name: str
    description: str | None
    status: ProjectStatus
    scope: list[ScopeEntry]
    created_at: datetime
    updated_at: datetime
