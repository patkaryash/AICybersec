"""Projects API: thin routers over backend/services/project_service.py."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from backend.api.deps import get_current_user
from backend.core.envelope import Envelope, PageData, ok, paginated
from backend.db.models import Project, User
from backend.db.session import get_db
from backend.schemas.projects import ProjectCreate, ProjectOut, ProjectUpdate
from backend.services import project_service

router = APIRouter(prefix="/api/v1/projects", tags=["projects"])


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "")


def _project_out(project: Project) -> ProjectOut:
    return ProjectOut.model_validate(project, from_attributes=True)


@router.post("", response_model=Envelope[ProjectOut], status_code=201)
def create_project(
    body: ProjectCreate,
    request: Request,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> Envelope[ProjectOut]:
    project = project_service.create_project(session, user=user, data=body)
    return ok(_project_out(project), _request_id(request))


@router.get("", response_model=Envelope[PageData[ProjectOut]])
def list_projects(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> Envelope[PageData[ProjectOut]]:
    rows, total = project_service.list_projects(
        session, user=user, page=page, page_size=page_size
    )
    return paginated(
        [_project_out(p) for p in rows],
        page,
        page_size,
        total,
        _request_id(request),
    )


@router.get("/{project_id}", response_model=Envelope[ProjectOut])
def get_project(
    project_id: uuid.UUID,
    request: Request,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> Envelope[ProjectOut]:
    project = project_service.get_project_for_user(session, project_id, user)
    return ok(_project_out(project), _request_id(request))


@router.patch("/{project_id}", response_model=Envelope[ProjectOut])
def update_project(
    project_id: uuid.UUID,
    body: ProjectUpdate,
    request: Request,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> Envelope[ProjectOut]:
    project = project_service.update_project(
        session, user=user, project_id=project_id, data=body
    )
    return ok(_project_out(project), _request_id(request))


@router.delete("/{project_id}", status_code=204)
def delete_project(
    project_id: uuid.UUID,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> None:
    project_service.archive_project(session, user=user, project_id=project_id)
