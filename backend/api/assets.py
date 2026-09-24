"""Assets API: thin routers over backend/services/asset_service.py."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from backend.api.deps import get_current_user
from backend.core.envelope import Envelope, PageData, ok, paginated
from backend.db.models import Asset, User
from backend.db.session import get_db
from backend.schemas.assets import AssetOut, AssetType
from backend.services import asset_service

router = APIRouter(prefix="/api/v1", tags=["assets"])


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "")


def _asset_out(asset: Asset) -> AssetOut:
    return AssetOut.model_validate(asset, from_attributes=True)


@router.get("/scans/{scan_id}/assets", response_model=Envelope[PageData[AssetOut]])
def list_assets(
    scan_id: uuid.UUID,
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    asset_type: AssetType | None = Query(default=None),
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> Envelope[PageData[AssetOut]]:
    rows, total = asset_service.list_assets_for_scan(
        session,
        user=user,
        scan_id=scan_id,
        page=page,
        page_size=page_size,
        asset_type=asset_type,
    )
    return paginated(
        [_asset_out(a) for a in rows], page, page_size, total, _request_id(request)
    )


@router.get("/assets/{asset_id}", response_model=Envelope[AssetOut])
def get_asset(
    asset_id: uuid.UUID,
    request: Request,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> Envelope[AssetOut]:
    asset = asset_service.get_asset_for_user(session, asset_id, user)
    return ok(_asset_out(asset), _request_id(request))
