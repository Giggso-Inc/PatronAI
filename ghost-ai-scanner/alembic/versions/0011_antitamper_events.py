"""patron antitamper events + enrollment

Revision ID: 0011_antitamper
Revises: 0010_object_blob_audits
Create Date: 2026-10-06

Cowork-parity anti-tamper ledger for Patron. Events FK users.id SET NULL.
Enrollment holds current agent/baseline version so official upgrades refresh
DB without inserting tamper rows.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0011_antitamper"
down_revision = "0010_object_blob_audits"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "patron_antitamper_events",
        sa.Column("tamper_id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("hostname", sa.String(256), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("orgs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("user_email", sa.String(320), nullable=True),
        sa.Column("file_path", sa.Text(), nullable=False),
        sa.Column("event_type", sa.String(16), nullable=False),
        sa.Column("old_hash", sa.String(64), nullable=True),
        sa.Column("new_hash", sa.String(64), nullable=True),
        sa.Column("restored", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("restore_ok", sa.Boolean(), nullable=True),
        sa.Column("agent_version", sa.String(64), nullable=True),
        sa.Column("baseline_version", sa.String(64), nullable=True),
        sa.Column("watcher_pid", sa.Integer(), nullable=True),
        sa.Column("check_interval_s", sa.Integer(), server_default=sa.text("30"), nullable=False),
        sa.Column("email_sent", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("hub_emitted", sa.Boolean(), server_default=sa.text("false"), nullable=False),
    )
    op.create_index("ix_patron_antitamper_user_id", "patron_antitamper_events", ["user_id"])
    op.create_index("ix_patron_antitamper_ts", "patron_antitamper_events", ["timestamp"])
    op.create_index("ix_patron_antitamper_hostname", "patron_antitamper_events", ["hostname"])
    op.create_index("ix_patron_antitamper_org_ts", "patron_antitamper_events", ["org_id", "timestamp"])

    op.create_table(
        "patron_antitamper_enrollment",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("orgs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("user_email", sa.String(320), nullable=True),
        sa.Column("hostname", sa.String(256), nullable=False),
        sa.Column("agent_version", sa.String(64), nullable=True),
        sa.Column("baseline_version", sa.String(64), nullable=True),
        sa.Column("baseline_id", sa.String(128), nullable=True),
        sa.Column("last_baseline_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("anti_tamper_enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("anti_tamper_restore", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("anti_tamper_interval_sec", sa.Integer(), server_default=sa.text("30"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("hostname", "user_email", name="uq_patron_antitamper_enrollment_host_user"),
    )
    op.create_index("ix_patron_antitamper_enroll_user", "patron_antitamper_enrollment", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_patron_antitamper_enroll_user", table_name="patron_antitamper_enrollment")
    op.drop_table("patron_antitamper_enrollment")
    op.drop_index("ix_patron_antitamper_org_ts", table_name="patron_antitamper_events")
    op.drop_index("ix_patron_antitamper_hostname", table_name="patron_antitamper_events")
    op.drop_index("ix_patron_antitamper_ts", table_name="patron_antitamper_events")
    op.drop_index("ix_patron_antitamper_user_id", table_name="patron_antitamper_events")
    op.drop_table("patron_antitamper_events")
