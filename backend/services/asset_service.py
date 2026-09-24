"""Asset service: read-only, scan-scoped, ownership via scan -> project."""
from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.core.errors import ApiError, ErrorCode
from backend.db.models import Asset, User
from backend.services.scan_service import get_scan_for_user


def get_asset_for_user(
    session: Session, asset_id: uuid.UUID, user: User
) -> Asset:
    """404 when missing or not owned (access via asset -> scan ->
    project -> owner_id). Consistent 404 prevents enumeration."""
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise ApiError(ErrorCode.FINDING_NOT_FOUND, "Asset does not exist.")
    get_scan_for_user(session, asset.scan_id, user)  # ownership gate (404)
    return asset


def list_assets_for_scan(
    session: Session,
    *,
    user: User,
    scan_id: uuid.UUID,
    page: int,
    page_size: int,
    asset_type: str | None = None,
) -> tuple[list[Asset], int]:
    """Assets for one visible scan, newest first (404 when invisible)."""
    get_scan_for_user(session, scan_id, user)
    query = select(Asset).where(Asset.scan_id == scan_id)
    if asset_type is not None:
        query = query.where(Asset.asset_type == asset_type)
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = (
        session.scalars(
            query.order_by(Asset.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        .all()
    )
    return list(rows), total
