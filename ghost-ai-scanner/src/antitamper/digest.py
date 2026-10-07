"""30-minute burst digest for continuous Patron antitamper findings.

While Hub collapses repeat ``patron_tamper`` alerts, every scan still inserts
``patron_antitamper_events``. After ~30 minutes of continuous findings, this
module rolls undigested rows **per user on this host** into one
``patron_tamper_digest`` Hub email (detailed Modified / Deleted / Added /
Baseline-fail breakdown).

Delivery (one emit → Hub matrix):
  • Security / Org admins → admin digest for that user
  • The affected user → developer digest for their own activity

Two users with continuous tamper ⇒ two digests ⇒ two admin emails + each
user gets their own developer email.
"""

from __future__ import annotations

import logging
import os
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

_log = logging.getLogger(__name__)

# Align digest cadence with continuous-tamper rollup (30 minutes).
DEFAULT_DIGEST_AFTER_SEC = int(os.environ.get("ANTITAMPER_DIGEST_AFTER_SEC") or 1800)
# Need at least this many local rows in the open burst before digesting.
MIN_BURST_EVENTS = int(os.environ.get("ANTITAMPER_DIGEST_MIN_EVENTS") or 2)
_MAX_PATHS_PER_ACTION = 20


def _aware(ts: datetime | None) -> datetime | None:
    if ts is None:
        return None
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts


def _unique_paths(items: list[str], *, limit: int = _MAX_PATHS_PER_ACTION) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for p in items:
        if not p or p in seen:
            continue
        seen.add(p)
        out.append(p)
        if len(out) >= limit:
            break
    return out


def _bullet_list(paths: list[str], *, total_unique: int | None = None) -> str:
    if not paths:
        return ""
    lines = [f"• {p}" for p in paths]
    more = (total_unique or len(paths)) - len(paths)
    if more > 0:
        lines.append(f"• +{more} more")
    return "\n".join(lines)


def _semicolon_list(paths: list[str], *, total_unique: int | None = None) -> str:
    if not paths:
        return ""
    label = "; ".join(paths)
    more = (total_unique or len(paths)) - len(paths)
    if more > 0:
        label = f"{label}; +{more} more"
    return label


def build_summary(rows: list[Any]) -> dict[str, Any]:
    """Turn ledger rows into detailed digest fields (by action + path)."""
    type_counts: Counter[str] = Counter()
    by_action: dict[str, list[str]] = {
        "MODIFIED": [],
        "DELETED": [],
        "ADDED": [],
        "BASE_FAIL": [],
    }
    emails: list[str] = []
    first_ts: datetime | None = None
    last_ts: datetime | None = None
    all_paths: list[str] = []

    for r in rows:
        et = str(getattr(r, "event_type", "") or "UNKNOWN").strip().upper() or "UNKNOWN"
        type_counts[et] += 1
        fp = str(getattr(r, "file_path", "") or "").strip()
        detail = str(getattr(r, "detail", "") or getattr(r, "reason", "") or "").strip()
        label = fp or detail or "(unknown)"
        if et in by_action:
            by_action[et].append(label)
        elif et not in ("DIGEST",):
            by_action.setdefault(et, []).append(label)
        if fp:
            all_paths.append(fp)
        em = (getattr(r, "user_email", None) or "") or ""
        if em and em not in emails:
            emails.append(em)
        ts = _aware(getattr(r, "timestamp", None))
        if ts is not None:
            if first_ts is None or ts < first_ts:
                first_ts = ts
            if last_ts is None or ts > last_ts:
                last_ts = ts

    modified = _unique_paths(by_action.get("MODIFIED") or [])
    deleted = _unique_paths(by_action.get("DELETED") or [])
    added = _unique_paths(by_action.get("ADDED") or [])
    base_fail = _unique_paths(by_action.get("BASE_FAIL") or [])
    # Unique across all actions for legacy file_path sample field
    sample_all = _unique_paths(all_paths, limit=12)

    modified_n = len(set(by_action.get("MODIFIED") or []))
    deleted_n = len(set(by_action.get("DELETED") or []))
    added_n = len(set(by_action.get("ADDED") or []))
    base_n = len(set(by_action.get("BASE_FAIL") or []))

    breakdown_parts: list[str] = []
    for key, n in (
        ("MODIFIED", type_counts.get("MODIFIED", 0)),
        ("DELETED", type_counts.get("DELETED", 0)),
        ("ADDED", type_counts.get("ADDED", 0)),
        ("BASE_FAIL", type_counts.get("BASE_FAIL", 0)),
    ):
        if n:
            breakdown_parts.append(f"{key}×{n}")
    for k, v in sorted(type_counts.items()):
        if k in ("MODIFIED", "DELETED", "ADDED", "BASE_FAIL", "DIGEST"):
            continue
        if v:
            breakdown_parts.append(f"{k}×{v}")
    breakdown = ", ".join(breakdown_parts)

    first_s = first_ts.isoformat(timespec="seconds") if first_ts else ""
    last_s = last_ts.isoformat(timespec="seconds") if last_ts else ""

    modified_list = _bullet_list(modified, total_unique=modified_n)
    deleted_list = _bullet_list(deleted, total_unique=deleted_n)
    added_list = _bullet_list(added, total_unique=added_n)
    base_fail_list = _bullet_list(base_fail, total_unique=base_n)

    detail = (
        f"{len(rows)} events/~30m — "
        f"modified {modified_n}, deleted {deleted_n}, "
        f"added {added_n}, baseline fail {base_n}"
    )

    return {
        "count": len(rows),
        "breakdown": breakdown,
        "file_path": _semicolon_list(sample_all, total_unique=len(set(all_paths)))
        or "(multiple)",
        "detail": detail,
        "timestamp": last_s or first_s,
        "user_email": emails[0] if emails else "",
        "event_type": "DIGEST",
        "restored": "No",
        "type_counts": dict(type_counts),
        "paths": sample_all,
        "first_ts": first_s,
        "last_ts": last_s,
        "tamper_ids": [str(getattr(r, "tamper_id", "")) for r in rows],
        # Detailed action lists for email KV table
        "modified_count": type_counts.get("MODIFIED", 0),
        "deleted_count": type_counts.get("DELETED", 0),
        "added_count": type_counts.get("ADDED", 0),
        "base_fail_count": type_counts.get("BASE_FAIL", 0),
        "modified_unique": modified_n,
        "deleted_unique": deleted_n,
        "added_unique": added_n,
        "base_fail_unique": base_n,
        "modified_list": modified_list,
        "deleted_list": deleted_list,
        "added_list": added_list,
        "base_fail_list": base_fail_list,
        "modified_paths": modified,
        "deleted_paths": deleted,
        "added_paths": added,
        "base_fail_paths": base_fail,
        "window_minutes": 30,
    }


def maybe_emit_burst_digest(
    *,
    hostname: str,
    org: str = "",
    user_email: str = "",
    digest_after_sec: int | None = None,
    min_events: int | None = None,
) -> dict[str, Any] | None:
    """If undigested burst for this user on this host is ready, emit one digest.

    Aggregation key: ``(hostname, user_email)`` — not the whole host. That way
    two users with continuous findings produce two digests (admins see both;
    each user only sees their own developer email).

    Returns summary dict when emitted, else None. Fail-open.
    """
    host = (hostname or "").strip()
    if not host:
        return None
    actor = (user_email or "").strip().lower()
    after = int(digest_after_sec if digest_after_sec is not None else DEFAULT_DIGEST_AFTER_SEC)
    need = int(min_events if min_events is not None else MIN_BURST_EVENTS)
    after = max(60, after)
    need = max(2, need)

    try:
        from db import get_session
        from db.models_antitamper import AntitamperEvent
    except Exception as e:
        _log.warning("antitamper digest imports failed: %s", e)
        return None

    now = datetime.now(timezone.utc)
    try:
        with get_session() as session:
            ts_col = AntitamperEvent.timestamp
            order_expr = ts_col.asc() if hasattr(ts_col, "asc") else ts_col
            q = session.query(AntitamperEvent).filter(
                AntitamperEvent.hostname == host,
                AntitamperEvent.digest_emitted.is_(False),
            )
            # Prefer the enrolled / scan user; fall back to rows with no email
            # only when the caller also has none (legacy / unknown actor).
            if actor:
                q = q.filter(AntitamperEvent.user_email == actor)
            else:
                q = q.filter(AntitamperEvent.user_email.is_(None))
            rows = q.order_by(order_expr).limit(500).all()
            if len(rows) < need:
                return None
            oldest = _aware(rows[0].timestamp)
            if oldest is None or (now - oldest) < timedelta(seconds=after):
                return None

            summary = build_summary(rows)
            actor = actor or str(summary.get("user_email") or "").strip().lower()
            window_key = (summary.get("first_ts") or oldest.isoformat()).replace(":", "")
            user_key = (actor or "unknown").replace("@", "_at_")[:80]
            eid = f"patron:tamper-digest:{host}:{user_key}:{window_key}"[:180]

            from notify.hub_alerts import emit_tamper_digest

            ok = emit_tamper_digest(
                org or "unknown",
                eid,
                detail=str(summary["detail"]),
                user=actor,
                device=host,
                payload={
                    "messaging_event": "patron_tamper_digest",
                    "event_type": "DIGEST",
                    "user": actor,
                    "user_email": actor,
                    "file_path": summary["file_path"],
                    "count": summary["count"],
                    "breakdown": summary["breakdown"],
                    "timestamp": summary["timestamp"],
                    "resource": summary["file_path"],
                    "resource_kind": "antitamper_digest",
                    "first_ts": summary["first_ts"],
                    "last_ts": summary["last_ts"],
                    "type_counts": summary["type_counts"],
                    "paths": summary["paths"][:20],
                    "window_minutes": 30,
                    "modified_count": summary["modified_count"],
                    "deleted_count": summary["deleted_count"],
                    "added_count": summary["added_count"],
                    "base_fail_count": summary["base_fail_count"],
                    "modified_list": summary["modified_list"],
                    "deleted_list": summary["deleted_list"],
                    "added_list": summary["added_list"],
                    "base_fail_list": summary["base_fail_list"],
                    "modified_paths": summary["modified_paths"],
                    "deleted_paths": summary["deleted_paths"],
                    "added_paths": summary["added_paths"],
                    "base_fail_paths": summary["base_fail_paths"],
                },
            )
            if not ok:
                _log.warning(
                    "antitamper digest emit failed host=%s user=%s count=%s",
                    host, actor or "-", len(rows),
                )
                return None

            ids = [r.tamper_id for r in rows]
            session.query(AntitamperEvent).filter(
                AntitamperEvent.tamper_id.in_(ids)
            ).update({"digest_emitted": True}, synchronize_session=False)
            session.commit()
            _log.info(
                "antitamper digest emitted host=%s user=%s count=%s window=%ss",
                host, actor or "-", summary["count"], after,
            )
            return summary
    except Exception as e:
        _log.warning("antitamper digest failed: %s", e)
        return None
