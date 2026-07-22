# =============================================================
# FILE: src/db/models_policy.py
# VERSION: 1.0.0
# UPDATED: 2026-06-29
# OWNER: Giggso Inc
# PURPOSE: Policy tables for the policy DB (ADR_2026-06-29):
#          approved_tools, blacklisted_tools, giggso_baseline_deny,
#          schema_migrations.
#          - domain_pattern / domain hold a PROVIDER glob (matched against
#            a finding's `provider`), covering domains AND tool ids.
#          - overrides_giggso: guarded org-only baseline override → ×0.5
#            tier. A DB CHECK enforces conditions C1 + reason/approver.
# =============================================================

import uuid
from datetime import date, datetime

from sqlalchemy import (
    Boolean, CheckConstraint, Date, DateTime, ForeignKey, Index, Integer,
    String, Text, func, text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from db.base import Base

_UUID_PK = dict(primary_key=True, server_default=text("gen_random_uuid()"))
_SCOPE_CK = "scope IN ('org','project','user')"
_SEV_CK = "severity IN ('LOW','MEDIUM','HIGH','CRITICAL')"
# Guard: an override must carry reason + approver, at org/project/user scope
# (C1' — admin-only is enforced server-side in governance_crud, not in SQL).
_OVERRIDE_CK = (
    "overrides_giggso = false OR "
    "(reason IS NOT NULL AND approved_by IS NOT NULL "
    "AND scope IN ('org','project','user'))"
)
# Deny-override guard (security_log 2026-07-03 D1-D7): same reason+approver
# rule, and only at a NARROWER grant scope (project/user) — an org can't
# "deny-override" its own org deny (that's just removing the deny).
_DENY_OVERRIDE_CK = (
    "overrides_deny = false OR "
    "(reason IS NOT NULL AND approved_by IS NOT NULL "
    "AND scope IN ('project','user'))"
)


class ApprovedTool(Base):
    """Whitelist entry at org/project/user scope. Match key = provider glob."""
    __tablename__ = "approved_tools"
    __table_args__ = (
        CheckConstraint(_SCOPE_CK, name="approved_scope"),
        CheckConstraint(_OVERRIDE_CK, name="giggso_override_guarded"),
        CheckConstraint(_DENY_OVERRIDE_CK, name="deny_override_guarded"),
        Index("ix_approved_tools_org_scope", "org_id", "scope"),
        Index("ix_approved_tools_user", "user_id"),
        Index("ix_approved_tools_project", "project_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), **_UUID_PK)
    org_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("orgs.id", ondelete="CASCADE")
    )
    scope: Mapped[str] = mapped_column(String(16), nullable=False)
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE")
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE")
    )
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    domain_pattern: Mapped[str] = mapped_column(String(512), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    added_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id")
    )
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    approved_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id")
    )
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[date | None] = mapped_column(Date)
    # Guarded baseline override (Phase E): true → giggso_override ×0.5 tier.
    overrides_giggso: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    # Guarded deny-override (2026-07-03): true → this scope-local approve
    # permits a tool a WIDER scope denied → deny_override_{project,user} tier.
    overrides_deny: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))


class BlacklistedTool(Base):
    """Deny entry at org/project/user scope. Match key = provider glob."""
    __tablename__ = "blacklisted_tools"
    __table_args__ = (
        CheckConstraint(_SCOPE_CK, name="blacklisted_scope"),
        CheckConstraint(_SEV_CK, name="blacklisted_severity"),
        Index("ix_blacklisted_org", "org_id", "domain"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), **_UUID_PK)
    org_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("orgs.id", ondelete="CASCADE")
    )
    scope: Mapped[str] = mapped_column(String(16), nullable=False)
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE")
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE")
    )
    name: Mapped[str | None] = mapped_column(String(256))
    domain: Mapped[str] = mapped_column(String(512), nullable=False)
    category: Mapped[str | None] = mapped_column(String(64))
    severity: Mapped[str | None] = mapped_column(String(16))
    reason: Mapped[str | None] = mapped_column(Text)
    added_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id")
    )
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class GiggsoBaselineDeny(Base):
    """Read-only mirror of the Giggso baseline denylist, seeded once at
    DB creation from config/unauthorized.csv. Tier-1 deny (×3.0)."""
    __tablename__ = "giggso_baseline_deny"
    __table_args__ = (CheckConstraint(_SEV_CK, name="giggso_baseline_severity"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), **_UUID_PK)
    name: Mapped[str | None] = mapped_column(String(256))
    category: Mapped[str | None] = mapped_column(String(64))
    domain: Mapped[str] = mapped_column(String(512), nullable=False)
    port: Mapped[int | None] = mapped_column(Integer)
    severity: Mapped[str | None] = mapped_column(String(16))
    notes: Mapped[str | None] = mapped_column(Text)
    seeded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    source: Mapped[str] = mapped_column(
        String(64), server_default=text("'config/unauthorized.csv'")
    )


class SchemaMigration(Base):
    """App-level migration / one-time-seed markers (e.g. the giggso seed guard).
    Distinct from Alembic's own alembic_version table."""
    __tablename__ = "schema_migrations"

    version: Mapped[str] = mapped_column(String(64), primary_key=True)
    applied_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
