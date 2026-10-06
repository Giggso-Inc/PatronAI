"""Persist Patron antitamper events + enrollment updates (fail-open callers)."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

_log = logging.getLogger(__name__)


def _parse_uuid(value: str | uuid.UUID | None) -> uuid.UUID | None:
    if value is None or value == "":
        return None
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError):
        return None


def record_event(finding: dict[str, Any], *, org_slug: str | None = None) -> str | None:
    """Insert patron_antitamper_events. Returns tamper_id string or None."""
    from db import get_session
    from db.models_antitamper import AntitamperEvent
    from db.models_identity import Org, User

    with get_session() as session:
        user_id = _parse_uuid(finding.get("user_id"))
        email = (finding.get("user_email") or "").strip().lower() or None
        org_id = None

        if email and user_id is None:
            user = session.query(User).filter(User.email == email).one_or_none()
            if user:
                user_id = user.id
                org_id = user.org_id

        if org_slug and org_id is None:
            org = session.query(Org).filter(Org.slug == org_slug).one_or_none()
            if org:
                org_id = org.id

        row = AntitamperEvent(
            hostname=str(finding.get("hostname") or "unknown")[:256],
            org_id=org_id,
            user_id=user_id,
            user_email=email,
            file_path=str(finding.get("file_path") or ""),
            event_type=str(finding.get("event_type") or "UNKNOWN")[:16],
            old_hash=finding.get("old_hash"),
            new_hash=finding.get("new_hash"),
            restored=bool(finding.get("restored")),
            restore_ok=finding.get("restore_ok"),
            agent_version=(finding.get("agent_version") or None),
            baseline_version=(finding.get("baseline_version") or None),
            watcher_pid=finding.get("watcher_pid"),
            check_interval_s=int(finding.get("check_interval_s") or 30),
            hub_emitted=False,
        )
        session.add(row)
        session.commit()
        return str(row.tamper_id)


def upsert_enrollment(
    *,
    hostname: str,
    user_email: str | None = None,
    user_id: str | uuid.UUID | None = None,
    org_slug: str | None = None,
    agent_version: str | None = None,
    baseline_version: str | None = None,
    baseline_id: str | None = None,
    enabled: bool = True,
    restore: bool = True,
    interval_sec: int = 30,
    heartbeat_only: bool = False,
) -> None:
    """Update enrollment on official baseline rebuild / heartbeat."""
    from db import get_session
    from db.models_antitamper import AntitamperEnrollment
    from db.models_identity import Org, User

    email = (user_email or "").strip().lower() or None
    uid = _parse_uuid(user_id)
    now = datetime.now(timezone.utc)

    with get_session() as session:
        org_id = None
        if email and uid is None:
            user = session.query(User).filter(User.email == email).one_or_none()
            if user:
                uid = user.id
                org_id = user.org_id
        if org_slug and org_id is None:
            org = session.query(Org).filter(Org.slug == org_slug).one_or_none()
            if org:
                org_id = org.id

        q = session.query(AntitamperEnrollment).filter(
            AntitamperEnrollment.hostname == hostname[:256],
            AntitamperEnrollment.user_email == email,
        )
        row = q.one_or_none()
        if row is None:
            row = AntitamperEnrollment(
                hostname=hostname[:256],
                user_email=email,
                user_id=uid,
                org_id=org_id,
            )
            session.add(row)

        row.last_heartbeat_at = now
        if not heartbeat_only:
            row.agent_version = agent_version
            row.baseline_version = baseline_version
            row.baseline_id = (baseline_id or "")[:128] or None
            row.last_baseline_at = now
            row.anti_tamper_enabled = bool(enabled)
            row.anti_tamper_restore = bool(restore)
            row.anti_tamper_interval_sec = int(interval_sec)
            if uid:
                row.user_id = uid
            if org_id:
                row.org_id = org_id
        session.commit()
