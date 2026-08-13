# =============================================================
# FILE: src/db/models_identity.py
# VERSION: 1.0.0
# UPDATED: 2026-06-29
# OWNER: Giggso Inc
# PURPOSE: Identity tables for the policy DB (ADR_2026-06-29):
#          orgs, users, projects, project_members. No passwords are stored —
#          identity only, for FK references and scope resolution.
#          Scopes are org/project/user (project scope dropped per amendment).
# =============================================================

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean, DateTime, ForeignKey, String, UniqueConstraint, func, text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from db.base import Base

_UUID_PK = dict(primary_key=True, server_default=text("gen_random_uuid()"))


class Org(Base):
    __tablename__ = "orgs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), **_UUID_PK)
    identity_org_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), unique=True)
    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(256), nullable=False)
    s3_bucket: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    created_by: Mapped[str | None] = mapped_column(String(256))


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), **_UUID_PK)
    identity_user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), unique=True)
    org_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("orgs.id", ondelete="CASCADE")
    )
    email: Mapped[str] = mapped_column(String(256), unique=True, nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(256))
    # is_org_admin gates org-scope edits AND the Giggso override (condition C1).
    is_org_admin: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    role: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'VIEWER'"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Project(Base):
    __tablename__ = "projects"
    __table_args__ = (UniqueConstraint("org_id", "slug", name="uq_projects_org_slug"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), **_UUID_PK)
    org_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("orgs.id", ondelete="CASCADE")
    )
    slug: Mapped[str] = mapped_column(String(64), nullable=False)
    display_name: Mapped[str] = mapped_column(String(256), nullable=False)
    # NULL for projects created directly in patron. Set together for projects
    # synced in from an upstream system (e.g. "ravenhub" + its group_id) so a
    # retried sync can look the row up instead of creating a duplicate.
    # Partial-unique on (org_id, external_source, external_ref) — see
    # alembic/versions/0005_project_external_ref.py.
    external_source: Mapped[str | None] = mapped_column(String(32))
    external_ref: Mapped[str | None] = mapped_column(String(128))


class ProjectMember(Base):
    __tablename__ = "project_members"

    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    is_project_admin: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
