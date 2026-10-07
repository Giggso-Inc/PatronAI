"""60-minute burst digest for continuous Patron antitamper findings.

While Hub collapses repeat ``patron_tamper`` alerts for ~60 minutes, every
scan still inserts ``patron_antitamper_events``. After the window, this
module rolls undigested rows for a host into one ``patron_tamper_digest``
Hub email (counts + sample paths) so continuous tampering is not silent.
"""

from __future__ import annotations

import logging
import os
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

_log = logging.getLogger(__name__)

# Align with Hub open-cause collapse (alert_ingest.py).
DEFAULT_DIGEST_AFTER_SEC = int(os.environ.get("ANTITAMPER_DIGEST_AFTER_SEC") or 3600)
# Need at least this many local rows in the open burst before digesting.
MIN_BURST_EVENTS = int(os.environ.get("ANTITAMPER_DIGEST_MIN_EVENTS") or 2)


def _aware(ts: datetime | None) -> datetime | None:
    if ts is None:
        return None
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts


def build_summary(rows: list[Any]) -> dict[str, Any]:
    """Turn ledger rows into template-friendly digest fields."""
    type_counts: Counter[str] = Counter()
    paths: list[str] = []
    seen_paths: set[str] = set()
    emails: list[str] = []
    first_ts: datetime | None = None
    last_ts: datetime | None = None
    for r in rows:
        et = str(getattr(r, "event_type", "") or "UNKNOWN")
        type_counts[et] += 1
        fp = str(getattr(r, "file_path", "") or "")
        if fp and fp not in seen_paths:
            seen_paths.add(fp)
            paths.append(fp)
        em = (getattr(r, "user_email", None) or "") or ""
        if em and em not in emails:
            emails.append(em)
        ts = _aware(getattr(r, "timestamp", None))
        if ts is not None:
            if first_ts is None or ts < first_ts:
                first_ts = ts
            if last_ts is None or ts > last_ts:
                last_ts = ts

    breakdown = ", ".join(f"{k}×{v}" for k, v in sorted(type_counts.items()))
    sample_paths = paths[:8]
    more = len(paths) - len(sample_paths)
    path_label = "; ".join(sample_paths)
    if more > 0:
        path_label = f"{path_label}; +{more} more"

    first_s = first_ts.isoformat(timespec="seconds") if first_ts else ""
    last_s = last_ts.isoformat(timespec="seconds") if last_ts else ""
    detail = (
        f"{len(rows)} local antitamper event(s) over ~60m ({breakdown}). "
        f"First: {first_s}; last: {last_s}. Paths: {path_label or '(none)'}."
    )
    return {
        "count": len(rows),
        "breakdown": breakdown,
        "file_path": path_label or "(multiple)",
        "detail": detail,
        "timestamp": last_s or first_s,
        "user_email": emails[0] if emails else "",
        "event_type": "DIGEST",
        "restored": "No",
        "type_counts": dict(type_counts),
        "paths": paths,
        "first_ts": first_s,
        "last_ts": last_s,
        "tamper_ids": [str(getattr(r, "tamper_id", "")) for r in rows],
    }


def maybe_emit_burst_digest(
    *,
    hostname: str,
    org: str = "",
    user_email: str = "",
    digest_after_sec: int | None = None,
    min_events: int | None = None,
) -> dict[str, Any] | None:
    """If undigested burst is old enough and large enough, emit one digest.

    Returns summary dict when emitted, else None. Fail-open.
    """
    host = (hostname or "").strip()
    if not host:
        return None
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
            rows = (
                session.query(AntitamperEvent)
                .filter(
                    AntitamperEvent.hostname == host,
                    AntitamperEvent.digest_emitted.is_(False),
                )
                .order_by(order_expr)
                .limit(500)
                .all()
            )
            if len(rows) < need:
                return None
            oldest = _aware(rows[0].timestamp)
            if oldest is None or (now - oldest) < timedelta(seconds=after):
                return None

            summary = build_summary(rows)
            actor = (user_email or summary.get("user_email") or "").strip()
            window_key = (summary.get("first_ts") or oldest.isoformat()).replace(":", "")
            eid = f"patron:tamper-digest:{host}:{window_key}"[:180]

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
                },
            )
            if not ok:
                _log.warning("antitamper digest emit failed host=%s count=%s", host, len(rows))
                return None

            ids = [r.tamper_id for r in rows]
            session.query(AntitamperEvent).filter(
                AntitamperEvent.tamper_id.in_(ids)
            ).update({"digest_emitted": True}, synchronize_session=False)
            session.commit()
            _log.info(
                "antitamper digest emitted host=%s count=%s window=%ss",
                host, summary["count"], after,
            )
            return summary
    except Exception as e:
        _log.warning("antitamper digest failed: %s", e)
        return None
