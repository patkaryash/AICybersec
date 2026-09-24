"""Asset DTOs."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel

AssetType = Literal["host", "service", "url"]


class AssetOut(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    project_id: uuid.UUID
    asset_type: AssetType
    value: str
    host: str | None
    port: int | None
    scheme: str | None
    attributes: dict[str, Any]
    source_tool: str
    created_at: datetime
    last_seen: datetime
