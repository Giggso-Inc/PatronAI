# =============================================================
# FILE: src/db/models_policy.py
# VERSION: 2.0.0
# UPDATED: 2026-07-31
# OWNER: Giggso Inc
# PURPOSE: Policy tables for the policy DB. Amends ADR_2026-06-29 per
#          ADR_2026-07-31-remove-giggso-baseline-scope-priority-waterfall:
#          approved_tools, blacklisted_tools, schema_migrations only.
#          - domain_pattern / domain hold a PROVIDER glob (matched against
#            a finding's `provider`), covering domains AND tool ids.
#          - No more Giggso baseline table / override columns — org owns
#            its own deny list outright, no guarded-override ceremony.
#          - OQ-4: the same (org_id, scope, project_id, user_id, pattern)
#            can never hold both an approve and a deny row. Enforced at the
#            write path (governance_crud._check_no_opposite_polarity) AND
#            by a DB trigger (added in alembic 0007) — belt and suspenders,
#            since the two tables can't share a single SQL CHECK/exclusion
#            constraint across each other.
# AUDIT LOG:
#   v1.0.0  2026-06-29  Initial.
#   v2.0.0  2026-07-31  Drop GiggsoBaselineDeny + overrides_giggso/
#                       overrides_deny columns (ADR_2026-07-31).
# =============================================================

import uuid
from datetime import date, datetime

from sqlalchemy import (
    CheckConstraint, Date, DateTime, ForeignKey, Index, String, Text, func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from db.base import Base

_UUID_PK = dict(primary_key=True, server_default=text("gen_random_uuid()"))
_SCOPE_CK = "scope IN ('org','project','user')"
_SEV_CK = "severity IN ('LOW','MEDIUM','HIGH','CRITICAL')"


class ApprovedTool(Base):
    """Whitelist entry at org/project/user scope. Match key = provider glob."""
    __tablename__ = "approved_tools"
    __table_args__ = (
        CheckConstraint(_SCOPE_CK, name="approved_scope"),
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


class RavenFlaggedTool(Base):
    """Pending MCP-governance flag forwarded from RavenHub (Phase 2 of the
    raven<->patron MCP-governance-sync initiative). NOT a third status on
    ApprovedTool/BlacklistedTool — those two mean "already classified"; this
    is the "raised, awaiting a patron admin's decision" queue that feeds the
    Provider Governance UI. Resolving one (Phase 3) writes the real decision
    into approved_tools/blacklisted_tools and marks this row resolved.

    Idempotent on raven's retry: the partial unique index
    uq_raven_flagged_tools_pending (project_id, provider_pattern) WHERE
    status='pending' means a re-forward of the same still-pending flag can
    only ever match/update the existing row, never duplicate it (see
    governance_crud.create_or_touch_raven_flag)."""
    __tablename__ = "raven_flagged_tools"
    __table_args__ = (
        CheckConstraint("status IN ('pending','approved','denied')",
                        name="ck_raven_flagged_tools_status"),
        Index("ix_raven_flagged_tools_org", "org_id"),
        Index("ix_raven_flagged_tools_project", "project_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), **_UUID_PK)
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    provider_pattern: Mapped[str] = mapped_column(String(256), nullable=False)
    requested_by: Mapped[str] = mapped_column(String(320), nullable=False)
    note: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default=text("'pending'"))
    source: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'ravenhub'"))
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    resolved_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SchemaMigration(Base):
    """App-level migration / one-time-seed markers (e.g. the giggso seed guard).
    Distinct from Alembic's own alembic_version table."""
    __tablename__ = "schema_migrations"

    version: Mapped[str] = mapped_column(String(64), primary_key=True)
    applied_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
