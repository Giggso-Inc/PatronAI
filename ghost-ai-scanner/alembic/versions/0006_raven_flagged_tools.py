"""raven_flagged_tools — pending MCP-governance flags forwarded from RavenHub

Revision ID: 0006_raven_flagged_tools
Revises: 0005_project_external_ref
Create Date: 2026-07-26

Phase 2 of the raven<->patron MCP-governance-sync initiative (see
MCP_GOVERNANCE_SYNC_PLAN.md at the dashboard repo root). When a RavenHub
Project Owner approves an ungoverned-MCP notice, raven POSTs a pending flag
here via routers/raven_enterprise_mcp_flags.py — NOT directly into
approved_tools/blacklisted_tools, since those two tables have no "pending,
awaiting a patron admin's decision" state (a row there means already
classified). A patron admin resolves the flag through the existing
Provider Governance UI (Phase 3), which writes the real decision into
approved_tools/blacklisted_tools and marks this row resolved.

Partial unique index keeps raven's forward idempotent: a retried POST for
the same still-pending (project, provider) flag updates the existing row
instead of creating a duplicate — same pattern as
uq_projects_external_ref (0005).
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "0006_raven_flagged_tools"
down_revision = "0005_project_external_ref"
branch_labels = None
depends_on = None

_UQ = "uq_raven_flagged_tools_pending"
_STATUS_CK = "ck_raven_flagged_tools_status"


def upgrade() -> None:
    op.create_table(
        "raven_flagged_tools",
        sa.Column("id", UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", UUID(as_uuid=True),
                  sa.ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("project_id", UUID(as_uuid=True),
                  sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("provider_pattern", sa.String(length=256), nullable=False),
        sa.Column("requested_by", sa.String(length=320), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="pending"),
        sa.Column("source", sa.String(length=32), nullable=False, server_default="ravenhub"),
        sa.Column("added_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("resolved_by", UUID(as_uuid=True),
                  sa.ForeignKey("users.id"), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_raven_flagged_tools_org", "raven_flagged_tools", ["org_id"])
    op.create_index("ix_raven_flagged_tools_project", "raven_flagged_tools", ["project_id"])
    op.execute(
        f"ALTER TABLE raven_flagged_tools ADD CONSTRAINT {_STATUS_CK} "
        "CHECK (status IN ('pending','approved','denied'))"
    )
    op.execute(
        f"CREATE UNIQUE INDEX {_UQ} ON raven_flagged_tools (project_id, provider_pattern) "
        "WHERE status = 'pending'"
    )


def downgrade() -> None:
    op.execute(f"DROP INDEX IF EXISTS {_UQ}")
    op.drop_index("ix_raven_flagged_tools_project", table_name="raven_flagged_tools")
    op.drop_index("ix_raven_flagged_tools_org", table_name="raven_flagged_tools")
    op.drop_table("raven_flagged_tools")
