"""object_blob_audits — append-only user audit for object-store puts

Revision ID: 0010_object_blob_audits
Revises: 0009_object_blobs
Create Date: 2026-10-06

Adds file_name on object_blobs and a new object_blob_audits table so every
put is retained with S3 key/file name, content hash, actor, and timestamp.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "0010_object_blob_audits"
down_revision = "0009_object_blobs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("object_blobs", sa.Column("file_name", sa.String(length=512), nullable=True))
    op.create_index("ix_object_blobs_file_name", "object_blobs", ["file_name"])

    op.create_table(
        "object_blob_audits",
        sa.Column("id", UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("bucket", sa.String(length=256), nullable=False),
        sa.Column("object_key", sa.String(length=1024), nullable=False),
        sa.Column("file_name", sa.String(length=512), nullable=True),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("content_type", sa.String(length=128), nullable=True),
        sa.Column("storage_mode", sa.String(length=16), nullable=True),
        sa.Column("action", sa.String(length=16), nullable=False, server_default="put"),
        sa.Column("actor_email", sa.String(length=320), nullable=True),
        sa.Column("actor_user_id", UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("subject_key_hash", sa.String(length=64), nullable=True),
        sa.Column("recorded_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_object_blob_audits_key", "object_blob_audits", ["bucket", "object_key"])
    op.create_index("ix_object_blob_audits_hash", "object_blob_audits", ["content_hash"])
    op.create_index("ix_object_blob_audits_actor", "object_blob_audits", ["actor_email"])
    op.create_index("ix_object_blob_audits_recorded_at", "object_blob_audits", ["recorded_at"])
    op.create_index("ix_object_blob_audits_file_name", "object_blob_audits", ["file_name"])


def downgrade() -> None:
    op.drop_index("ix_object_blob_audits_file_name", table_name="object_blob_audits")
    op.drop_index("ix_object_blob_audits_recorded_at", table_name="object_blob_audits")
    op.drop_index("ix_object_blob_audits_actor", table_name="object_blob_audits")
    op.drop_index("ix_object_blob_audits_hash", table_name="object_blob_audits")
    op.drop_index("ix_object_blob_audits_key", table_name="object_blob_audits")
    op.drop_table("object_blob_audits")
    op.drop_index("ix_object_blobs_file_name", table_name="object_blobs")
    op.drop_column("object_blobs", "file_name")