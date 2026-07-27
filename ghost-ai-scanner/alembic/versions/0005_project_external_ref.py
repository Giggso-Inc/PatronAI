"""project external source/ref — idempotent sync target for RavenHub-created projects

Revision ID: 0005_project_external_ref
Revises: 0004_deny_override
Create Date: 2026-07-24

Adds projects.external_source / projects.external_ref so a project created by
an upstream system (RavenHub) can be looked up idempotently (retry-safe)
instead of relying only on the (org_id, slug) unique constraint, which
collides on cosmetic slug differences rather than "is this the same upstream
project". Both columns stay NULL for projects created directly in patron (the
existing manual path), so no backfill is required. Partial unique index
enforces one patron project per (org_id, external_source, external_ref) once
an upstream ref is recorded.
"""
from alembic import op
import sqlalchemy as sa

revision = "0005_project_external_ref"
down_revision = "0004_deny_override"
branch_labels = None
depends_on = None

_UQ = "uq_projects_external_ref"


def upgrade() -> None:
    op.add_column("projects", sa.Column("external_source", sa.String(length=32), nullable=True))
    op.add_column("projects", sa.Column("external_ref", sa.String(length=128), nullable=True))
    op.execute(
        f"CREATE UNIQUE INDEX {_UQ} ON projects (org_id, external_source, external_ref) "
        "WHERE external_ref IS NOT NULL AND external_source IS NOT NULL"
    )


def downgrade() -> None:
    op.execute(f"DROP INDEX IF EXISTS {_UQ}")
    op.drop_column("projects", "external_ref")
    op.drop_column("projects", "external_source")
