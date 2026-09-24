"""Project service: CRUD + ownership gates.

Ownership model: user -> project (owner_id). get_project_for_user is
THE ownership gate for projects (404 when missing or not owned; admins
bypass the owner check) - routers never duplicate this logic.
"""
from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.core.errors import ApiError, ErrorCode
from backend.db.models import Project, User
from backend.schemas.projects import ProjectCreate, ProjectUpdate
from backend.services.scope_service import validate_scope


def get_project_for_user(
    session: Session, project_id: uuid.UUID, user: User
) -> Project:
    """404 PROJECT_NOT_FOUND when the project is missing OR not owned by
    the user (admins bypass the owner check). Consistent 404 prevents
    resource enumeration."""
    project = session.get(Project, project_id)
    if project is None:
        raise ApiError(ErrorCode.PROJECT_NOT_FOUND, "Project does not exist.")
    if user.role != "admin" and project.owner_id != user.id:
        raise ApiError(ErrorCode.PROJECT_NOT_FOUND, "Project does not exist.")
    return project


def create_project(session: Session, *, user: User, data: ProjectCreate) -> Project:
    project = Project(
        owner_id=user.id,
        name=data.name,
        description=data.description,
        scope=validate_scope(data.scope),
    )
    session.add(project)
    session.commit()
    session.refresh(project)
    return project


def list_projects(
    session: Session, *, user: User, page: int, page_size: int
) -> tuple[list[Project], int]:
    """Projects visible to the user (owned only; admins see all), newest first."""
    query = select(Project)
    if user.role != "admin":
        query = query.where(Project.owner_id == user.id)
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = (
        session.scalars(
            query.order_by(Project.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        .all()
    )
    return list(rows), total


def update_project(
    session: Session, *, user: User, project_id: uuid.UUID, data: ProjectUpdate
) -> Project:
    project = get_project_for_user(session, project_id, user)
    if data.name is not None:
        project.name = data.name
    if data.description is not None:
        project.description = data.description
    if data.scope is not None:
        # Scope changes never affect existing scans - their
        # target_snapshot was copied at scan creation (the anchor).
        project.scope = validate_scope(data.scope)
    if data.status is not None:
        project.status = data.status
    session.commit()
    session.refresh(project)
    return project


def archive_project(session: Session, *, user: User, project_id: uuid.UUID) -> None:
    """DELETE is an archive: status=archived, never a physical delete."""
    project = get_project_for_user(session, project_id, user)
    project.status = "archived"
    session.commit()
