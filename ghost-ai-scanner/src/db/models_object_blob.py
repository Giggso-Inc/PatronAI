# =============================================================
# FILE: src/db/models_object_blob.py
# PURPOSE: S3/object-store registry + append-only user audit.
#          object_blobs = latest state per key (hash, user, times).
#          object_blob_audits = one row per put (user audit trail).
# =============================================================

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger, DateTime, ForeignKey, Index, String, UniqueConstraint, func, text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from db.base import Base

_UUID_PK = dict(primary_key=True, server_default=text("gen_random_uuid()"))


class ObjectBlob(Base):
    """Current state for one (bucket, object_key)."""

    __tablename__ = "object_blobs"
    __table_args__ = (
        UniqueConstraint("bucket", "object_key", name="uq_object_blobs_bucket_key"),
        Index("ix_object_blobs_content_hash", "content_hash"),
        Index("ix_object_blobs_created_by", "created_by"),
        Index("ix_object_blobs_updated_at", "updated_at"),
        Index("ix_object_blobs_file_name", "file_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), **_UUID_PK)
    bucket: Mapped[str] = mapped_column(String(256), nullable=False)
    object_key: Mapped[str] = mapped_column(String(1024), nullable=False)
    file_name: Mapped[str | None] = mapped_column(String(512))
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default=text("0"))
    content_type: Mapped[str | None] = mapped_column(String(128))
    storage_mode: Mapped[str | None] = mapped_column(String(16))
    created_by: Mapped[str | None] = mapped_column(String(320))
    updated_by: Mapped[str | None] = mapped_column(String(320))
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    updated_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class ObjectBlobAudit(Base):
    """Append-only user audit: every successful put gets a row."""

    __tablename__ = "object_blob_audits"
    __table_args__ = (
        Index("ix_object_blob_audits_key", "bucket", "object_key"),
        Index("ix_object_blob_audits_hash", "content_hash"),
        Index("ix_object_blob_audits_actor", "actor_email"),
        Index("ix_object_blob_audits_recorded_at", "recorded_at"),
        Index("ix_object_blob_audits_file_name", "file_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), **_UUID_PK)
    bucket: Mapped[str] = mapped_column(String(256), nullable=False)
    object_key: Mapped[str] = mapped_column(String(1024), nullable=False)
    file_name: Mapped[str | None] = mapped_column(String(512))
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default=text("0"))
    content_type: Mapped[str | None] = mapped_column(String(128))
    storage_mode: Mapped[str | None] = mapped_column(String(16))
    action: Mapped[str] = mapped_column(String(16), nullable=False, server_default=text("'put'"))
    actor_email: Mapped[str | None] = mapped_column(String(320))
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    # Privacy-safe subject from key paths like chat/{sha16}/... when email unknown.
    subject_key_hash: Mapped[str | None] = mapped_column(String(64))
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )