"""object_blobs — content-hash ledger for object-store puts

Revision ID: 0009_object_blobs
Revises: 0008_device_count
Create Date: 2026-10-06

Every successful ObjectStore / S3-compatible put upserts one row keyed by
(bucket, object_key). content_hash is SHA-256 of the body; created_* is set
on first write, updated_* on every subsequent write. Actor email + optional
users.id FK come from the request contextvar (Raven identity).
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "0009_object_blobs"
down_revision = "0008_device_count"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "object_blobs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("bucket", sa.String(length=256), nullable=False),
        sa.Column("object_key", sa.String(length=1024), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("content_type", sa.String(length=128), nullable=True),
        sa.Column("storage_mode", sa.String(length=16), nullable=True),
        sa.Column("created_by", sa.String(length=320), nullable=True),
        sa.Column("updated_by", sa.String(length=320), nullable=True),
        sa.Column("created_by_user_id", UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("updated_by_user_id", UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("bucket", "object_key", name="uq_object_blobs_bucket_key"),
    )
    op.create_index("ix_object_blobs_content_hash", "object_blobs", ["content_hash"])
    op.create_index("ix_object_blobs_created_by", "object_blobs", ["created_by"])
    op.create_index("ix_object_blobs_updated_at", "object_blobs", ["updated_at"])


def downgrade() -> None:
    op.drop_index("ix_object_blobs_updated_at", table_name="object_blobs")
    op.drop_index("ix_object_blobs_created_by", table_name="object_blobs")
    op.drop_index("ix_object_blobs_content_hash", table_name="object_blobs")
    op.drop_table("object_blobs")