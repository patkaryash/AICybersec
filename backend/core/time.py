"""UTC ISO-8601 timestamp formatting for API payloads.

All API timestamps are UTC ISO-8601 with the Z suffix,
e.g. 2026-09-23T15:40:00Z.
"""
from __future__ import annotations

from datetime import datetime, timezone


def utc_iso(dt: datetime | None = None) -> str:
    """Format a datetime as UTC ISO-8601 with Z suffix."""
    dt = dt or datetime.now(timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
