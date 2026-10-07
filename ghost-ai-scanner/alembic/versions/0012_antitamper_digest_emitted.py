"""Add digest_emitted flag for antitamper burst digests

Revision ID: 0012_antitamper_digest
Revises: 0011_antitamper
Create Date: 2026-10-07

Marks local ledger rows that have already been rolled into a 30-minute
burst digest Hub email so continuous tampering during Hub open-collapse
still surfaces once as an aggregate.
"""
from alembic import op
import sqlalchemy as sa

revision = "0012_antitamper_digest"
down_revision = "0011_antitamper"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "patron_antitamper_events",
        sa.Column(
            "digest_emitted",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_patron_antitamper_digest_host",
        "patron_antitamper_events",
        ["hostname", "digest_emitted", "timestamp"],
    )


def downgrade() -> None:
    op.drop_index("ix_patron_antitamper_digest_host", table_name="patron_antitamper_events")
    op.drop_column("patron_antitamper_events", "digest_emitted")
