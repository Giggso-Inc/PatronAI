# =============================================================
# FILE: src/db/object_blob_ledger.py
# PURPOSE: Fail-open S3/object put recorder.
#          - Upserts object_blobs (latest key → hash + user + times)
#          - Inserts object_blob_audits (append-only user audit)
# =============================================================

from __future__ import annotations

import hashlib
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
    """Clear the request/job actor binding (usually for tests)."""
    _object_actor.set((None, None))


def get_object_actor() -> _Actor:
    """Return ``(email, user_id)`` currently bound for object puts."""
    return _object_actor.get()


@contextmanager
def object_actor(
    email: str | None = None,
    user_id: uuid.UUID | str | None = None,
) -> Iterator[None]:
    """Temporarily bind actor; always restores the previous binding on exit."""
    prev = _object_actor.get()
    set_object_actor(email=email, user_id=user_id)
    try:
        yield
    finally:
        _object_actor.set(prev)


def content_sha256(body: bytes | bytearray | memoryview | str | None) -> str:
    """SHA-256 hex digest of object body bytes (empty body → empty-hash)."""
    if body is None:
        data = b""
    elif isinstance(body, str):
        data = body.encode("utf-8")
    else:
        data = bytes(body)
    return hashlib.sha256(data).hexdigest()


def file_name_from_key(key: str) -> str:
    """Last path segment of an object key (POSIX)."""
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


def _normalize_email(value: str | None) -> str | None:
    cand = (value or "").strip().lower()
    if cand and _EMAIL_RE.match(cand):
        return cand
    return None


def _subject_hash_from_key(key: str) -> str | None:
    m = _CHAT_HASH_RE.match(key or "")
    return m.group(1) if m else None


def _resolve_verified_actor(
    actor_email: str | None,
    actor_user_id: uuid.UUID | str | None,
) -> _Actor:
    """Verified actors only: explicit args, then contextvar. Never JSON body."""
    ctx_email, ctx_uid = get_object_actor()
    email = _normalize_email(actor_email) or ctx_email
    uid = _parse_uuid(actor_user_id) or ctx_uid
    return email, uid


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


def _upsert_blob(
    session: Any,
    *,
    bucket: str,
    key: str,
    fname: str,
    digest: str,
    size: int,
    content_type: str | None,
    storage_mode: str | None,
    email: str | None,
    uid: uuid.UUID | None,
    now: datetime,
) -> None:
    """Atomic upsert via ON CONFLICT — no TOCTOU SELECT/INSERT race."""
    from db.models_object_blob import ObjectBlob
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    values = {
        "bucket": bucket,
        "object_key": key,
        "file_name": fname or None,
        "content_hash": digest,
        "size_bytes": size,
        "content_type": content_type,
        "storage_mode": storage_mode,
        "created_by": email,
        "updated_by": email,
        "created_by_user_id": uid,
        "updated_by_user_id": uid,
        "created_at": now,
        "updated_at": now,
    }
    update_set = {
        "content_hash": digest,
        "size_bytes": size,
        "updated_by": email,
        "updated_by_user_id": uid,
        "updated_at": now,
    }
    if fname:
        update_set["file_name"] = fname
    if content_type is not None:
        update_set["content_type"] = content_type
    if storage_mode is not None:
        update_set["storage_mode"] = storage_mode
    # Preserve original created_by when already set.
    from sqlalchemy import case

    stmt = (
        pg_insert(ObjectBlob)
        .values(**values)
        .on_conflict_do_update(
            constraint="uq_object_blobs_bucket_key",
            set_={
                **update_set,
                "created_by": case(
                    (ObjectBlob.created_by.is_(None), email),
                    else_=ObjectBlob.created_by,
                ),
                "created_by_user_id": case(
                    (ObjectBlob.created_by_user_id.is_(None), uid),
                    else_=ObjectBlob.created_by_user_id,
                ),
            },
        )
    )
    session.execute(stmt)


def _append_audit(
    session: Any,
    *,
    bucket: str,
    key: str,
    fname: str,
    digest: str,
    size: int,
    content_type: str | None,
    storage_mode: str | None,
    email: str | None,
    uid: uuid.UUID | None,
    subject_hash: str | None,
    now: datetime,
) -> None:
    from db.models_object_blob import ObjectBlobAudit

    session.add(ObjectBlobAudit(
        bucket=bucket,
        object_key=key,
        file_name=fname or None,
        content_hash=digest,
        size_bytes=size,
        content_type=content_type,
        storage_mode=storage_mode,
        action="put",
        actor_email=email,
        actor_user_id=uid,
        subject_key_hash=subject_hash,
        recorded_at=now,
    ))


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
    email, uid = _resolve_verified_actor(actor_email, actor_user_id)

    from db.engine import get_session

    with get_session() as session:
        _upsert_blob(
            session,
            bucket=bucket,
            key=key,
            fname=fname,
            digest=digest,
            size=len(data),
            content_type=content_type,
            storage_mode=storage_mode,
            email=email,
            uid=uid,
            now=now,
        )
        _append_audit(
            session,
            bucket=bucket,
            key=key,
            fname=fname,
            digest=digest,
            size=len(data),
            content_type=content_type,
            storage_mode=storage_mode,
            email=email,
            uid=uid,
            subject_hash=subject_hash,
            now=now,
        )
        session.commit()
