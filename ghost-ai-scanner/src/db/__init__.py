# =============================================================
# FILE: src/db/__init__.py
# VERSION: 1.0.0
# UPDATED: 2026-06-29
# OWNER: Giggso Inc
# PURPOSE: Policy/identity DB package (ADR_2026-06-29). Importing this
#          package registers every model on Base.metadata so Alembic and
#          create_all() see the full schema.
# =============================================================

from db.base import Base
from db.engine import get_engine, get_session, database_url, reset_engine
from db.models_identity import Org, User, Project, ProjectMember
from db.models_policy import (
    ApprovedTool, BlacklistedTool, GiggsoBaselineDeny, SchemaMigration,
)

__all__ = [
    "Base", "get_engine", "get_session", "database_url", "reset_engine",
    "Org", "User", "Project", "ProjectMember",
    "ApprovedTool", "BlacklistedTool", "GiggsoBaselineDeny", "SchemaMigration",
]
