"""backend.schemas: Pydantic API DTOs.

API contracts are decoupled from SQLAlchemy models - services convert
ORM rows into these schemas; routers return only these.
"""
from backend.schemas.assets import AssetOut
from backend.schemas.auth import (
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    UserOut,
)
from backend.schemas.common import PaginationParams
from backend.schemas.events import AgentEventOut, ToolRunOut
from backend.schemas.findings import FindingOut
from backend.schemas.projects import (
    ProjectCreate,
    ProjectOut,
    ProjectUpdate,
    ScopeEntry,
)
from backend.schemas.scans import (
    FindingsCount,
    ScanCreate,
    ScanOut,
)

__all__ = [
    "AgentEventOut",
    "AssetOut",
    "FindingsCount",
    "FindingOut",
    "LoginRequest",
    "PaginationParams",
    "ProjectCreate",
    "ProjectOut",
    "ProjectUpdate",
    "RegisterRequest",
    "ScanCreate",
    "ScanOut",
    "ScopeEntry",
    "TokenResponse",
    "ToolRunOut",
    "UserOut",
]
