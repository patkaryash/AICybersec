"""Asset DTOs (Phase 4A: attack-surface foundation).

Asset types: host | subdomain | domain | service | url | endpoint.
``parent_asset_id`` links a node to its parent surface node in the same
scan (e.g. endpoint -> url, subdomain -> domain); NULL when the parent
is unknown - never guessed.

Attributes conventions (free-form dict, queryable JSONB):
- subdomain: {parent_domain, source, verification_status,
  dns_a?, dns_aaaa?, dns_cname?}
- host: may carry DNS enrichment {dns_a?, dns_aaaa?, dns_cname?}
  (DATA only - never authorization).
- endpoint: {source_page?, crawl_depth?, http_method?}
- service/url: unchanged from Phase 3.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel

AssetType = Literal["host", "subdomain", "domain", "service", "url", "endpoint"]


class AssetOut(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    project_id: uuid.UUID
    asset_type: AssetType
    value: str
    host: str | None
    port: int | None
    scheme: str | None
    parent_asset_id: uuid.UUID | None
    attributes: dict[str, Any]
    source_tool: str
    created_at: datetime
    last_seen: datetime
