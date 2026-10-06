# =============================================================
# FILE: src/db/models_antitamper.py
# PURPOSE: Patron anti-tamper ledger + agent enrollment (Cowork parity).
#          Events FK to users.id (SET NULL). Official upgrades update
#          enrollment only — they do not insert tamper rows.
# =============================================================

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from db.base import Base

_UUID_PK = dict(primary_key=True, server_default=text("gen_random_uuid()"))


class AntitamperEvent(Base):
    """Append-only integrity findings for the Patron agent install tree."""

    __tablename__ = "patron_antitamper_events"
    __table_args__ = (
        Index("ix_patron_antitamper_user_id", "user_id"),
        Index("ix_patron_antitamper_ts", "timestamp"),
        Index("ix_patron_antitamper_hostname", "hostname"),
        Index("ix_patron_antitamper_org_ts", "org_id", "timestamp"),
    )

    tamper_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), **_UUID_PK)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    hostname: Mapped[str] = mapped_column(String(256), nullable=False)
    org_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("orgs.id", ondelete="SET NULL")
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    user_email: Mapped[str | None] = mapped_column(String(320))

    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    event_type: Mapped[str] = mapped_column(String(16), nullable=False)
    old_hash: Mapped[str | None] = mapped_column(String(64))
    new_hash: Mapped[str | None] = mapped_column(String(64))

    restored: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    restore_ok: Mapped[bool | None] = mapped_column(Boolean)
    agent_version: Mapped[str | None] = mapped_column(String(64))
    baseline_version: Mapped[str | None] = mapped_column(String(64))
    watcher_pid: Mapped[int | None] = mapped_column(Integer)
    check_interval_s: Mapped[int] = mapped_column(Integer, server_default=text("30"), nullable=False)
    email_sent: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    hub_emitted: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)


class AntitamperEnrollment(Base):
    """Per-host current baseline / feature flags (mutable; upgrades land here)."""

    __tablename__ = "patron_antitamper_enrollment"
    __table_args__ = (
        UniqueConstraint("hostname", "user_email", name="uq_patron_antitamper_enrollment_host_user"),
        Index("ix_patron_antitamper_enroll_user", "user_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), **_UUID_PK)
    org_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("orgs.id", ondelete="SET NULL")
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    user_email: Mapped[str | None] = mapped_column(String(320))
    hostname: Mapped[str] = mapped_column(String(256), nullable=False)

    agent_version: Mapped[str | None] = mapped_column(String(64))
    baseline_version: Mapped[str | None] = mapped_column(String(64))
    baseline_id: Mapped[str | None] = mapped_column(String(128))
    last_baseline_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    anti_tamper_enabled: Mapped[bool] = mapped_column(
        Boolean, server_default=text("false"), nullable=False
    )
    anti_tamper_restore: Mapped[bool] = mapped_column(
        Boolean, server_default=text("true"), nullable=False
    )
    anti_tamper_interval_sec: Mapped[int] = mapped_column(
        Integer, server_default=text("30"), nullable=False
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
