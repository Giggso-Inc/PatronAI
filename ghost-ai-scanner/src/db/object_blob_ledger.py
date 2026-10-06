# =============================================================
# FILE: src/db/object_blob_ledger.py
# PURPOSE: Fail-open S3/object put recorder.
#          - Upserts object_blobs (latest key → hash + user + times)
#          - Inserts object_blob_audits (append-only user audit)
# =============================================================

from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, Iterator, Optional

_log = logging.getLogger("marauder-scan.object_blob_ledger")

_Actor = tuple[Optional[str], Optional[uuid.UUID]]
_object_actor: ContextVar[_Actor] = ContextVar("object_actor", default=(None, None))

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_CHAT_HASH_RE = re.compile(r"^chat/([0-9a-f]{16})/", re.IGNORECASE)


def set_object_actor(
    email: str | None = None,
    user_id: uuid.UUID | str | None = None,
) -> None:
    """Bind the current request/job actor for subsequent object puts."""
    uid: uuid.UUID | None = None
    if user_id is not None:
        try:
            uid = user_id if isinstance(user_id, uuid.UUID) else uuid.UUID(str(user_id))
        except (ValueError, TypeError):
            uid = None
    label = (email or "").strip().lower() or None
    _object_actor.set((label, uid))


def clear_object_actor() -> None:
    _object_actor.set((None, None))


def get_object_actor() -> _Actor:
    return _object_actor.get()


@contextmanager
def object_actor(
    email: str | None = None,
    user_id: uuid.UUID | str | None = None,
) -> Iterator[None]:
    prev = _object_actor.get()
    set_object_actor(email=email, user_id=user_id)
    try:
        yield
    finally:
        _object_actor.set(prev)


def content_sha256(body: bytes | bytearray | memoryview | str | None) -> str:
    if body is None:
        data = b""
    elif isinstance(body, str):
        data = body.encode("utf-8")
    else:
        data = bytes(body)
    return hashlib.sha256(data).hexdigest()


def file_name_from_key(key: str) -> str:
    name = PurePosixPath((key or "").strip()).name
    return name or (key or "").strip() or ""


def _coerce_body(body: Any) -> bytes:
    if body is None:
        return b""
    if hasattr(body, "read"):
        return _coerce_body(body.read())
    if isinstance(body, str):
        return body.encode("utf-8")
    if isinstance(body, memoryview):
        return body.tobytes()
    return bytes(body)


def _parse_uuid(value: Any) -> uuid.UUID | None:
    if value is None:
        return None
    try:
        return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))
    except (ValueError, TypeError):
        return None


def _email_from_body(data: bytes) -> str | None:
    """Best-effort pull of a user email from JSON payloads."""
    if not data or data[:1] not in (b"{", b"["):
        return None
    try:
        payload = json.loads(data.decode("utf-8", errors="ignore"))
    except Exception:
        return None
    if isinstance(payload, list) and payload:
        payload = payload[0]
    if not isinstance(payload, dict):
        return None
    for key in (
        "email", "user_email", "actor_user", "recipient_email",
        "added_by", "created_by", "username", "user",
    ):
        raw = payload.get(key)
        if isinstance(raw, str):
            cand = raw.strip().lower()
            if _EMAIL_RE.match(cand):
                return cand
    return None


def _subject_hash_from_key(key: str) -> str | None:
    m = _CHAT_HASH_RE.match(key or "")
    return m.group(1) if m else None


def record_object_put(
    *,
    bucket: str,
    key: str,
    body: Any = b"",
    content_type: str | None = None,
    storage_mode: str | None = None,
    actor_email: str | None = None,
    actor_user_id: uuid.UUID | str | None = None,
) -> None:
    """Upsert current blob + append audit row. Fail-open on any error."""
    try:
        _record_object_put_inner(
            bucket=bucket,
            key=key,
            body=body,
            content_type=content_type,
            storage_mode=storage_mode,
            actor_email=actor_email,
            actor_user_id=actor_user_id,
        )
    except Exception as exc:
        _log.warning("object_blob ledger skip [%s/%s]: %s", bucket, key, exc)


def _record_object_put_inner(
    *,
    bucket: str,
    key: str,
    body: Any,
    content_type: str | None,
    storage_mode: str | None,
    actor_email: str | None,
    actor_user_id: uuid.UUID | str | None,
) -> None:
    bucket = (bucket or "").strip()
    key = (key or "").strip()
    if not bucket or not key:
        return

    data = _coerce_body(body)
    digest = content_sha256(data)
    fname = file_name_from_key(key)
    now = datetime.now(timezone.utc)
    subject_hash = _subject_hash_from_key(key)

    ctx_email, ctx_uid = get_object_actor()
    email = (actor_email or "").strip().lower() or ctx_email or _email_from_body(data)
    uid = _parse_uuid(actor_user_id) or ctx_uid

    from db.engine import get_session
    from db.models_object_blob import ObjectBlob, ObjectBlobAudit
    from sqlalchemy import select

    with get_session() as session:
        row = session.execute(
            select(ObjectBlob).where(
                ObjectBlob.bucket == bucket,
                ObjectBlob.object_key == key,
            )
        ).scalar_one_or_none()

        if row is None:
            row = ObjectBlob(
                bucket=bucket,
                object_key=key,
                file_name=fname or None,
                content_hash=digest,
                size_bytes=len(data),
                content_type=content_type,
                storage_mode=storage_mode,
                created_by=email,
                updated_by=email,
                created_by_user_id=uid,
                updated_by_user_id=uid,
                created_at=now,
                updated_at=now,
            )
            session.add(row)
        else:
            row.content_hash = digest
            row.size_bytes = len(data)
            row.file_name = fname or row.file_name
            if content_type is not None:
                row.content_type = content_type
            if storage_mode is not None:
                row.storage_mode = storage_mode
            row.updated_by = email
            row.updated_by_user_id = uid
            row.updated_at = now
            if row.created_by is None and email:
                row.created_by = email
            if row.created_by_user_id is None and uid is not None:
                row.created_by_user_id = uid

        session.add(ObjectBlobAudit(
            bucket=bucket,
            object_key=key,
            file_name=fname or None,
            content_hash=digest,
            size_bytes=len(data),
            content_type=content_type,
            storage_mode=storage_mode,
            action="put",
            actor_email=email,
            actor_user_id=uid,
            subject_key_hash=subject_hash,
            recorded_at=now,
        ))
        session.commit()