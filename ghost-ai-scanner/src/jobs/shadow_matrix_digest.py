"""Daily Patron -> Hub alerts for continued shadow use and stale decisions.

Sheet rows (Incidents & Escalations, in-app):
  more users continue to use the discovered shadow tool
  shadow tool decision pending more than 72 hours
  shadow tool decision pending more than 7 days

Runs once per UTC day. Hub dedupes on source_event_id, so a restart the same
day does not send a second copy.
"""

from __future__ import annotations

import logging
import os
import threading
from datetime import datetime, timezone

from notify.hub_alerts import emit_continued_use, emit_pending_decisions

log = logging.getLogger("marauder-scan.jobs.shadow_matrix_digest")

_HOUR = int(os.environ.get("PATRON_SHADOW_DIGEST_HOUR", "8"))


def due_alerts(flags, *, now: datetime | None = None) -> list[dict]:
    """Decide which sheet alerts a pending-flag list should send today.

    Each flag needs provider_pattern, added_at, device_count.
    """
    now = now or datetime.now(timezone.utc)
    day = now.date().isoformat()
    out: list[dict] = []
    for flag in flags:
        added = getattr(flag, "added_at", None)
        if added is None:
            continue
        if added.tzinfo is None:
            added = added.replace(tzinfo=timezone.utc)
        age_h = (now - added).total_seconds() / 3600
        tool = getattr(flag, "provider_pattern", "") or ""
        users = int(getattr(flag, "device_count", 0) or 0)
        org = getattr(flag, "org_slug", "") or ""
        if users >= 2:
            out.append({
                "kind": "continued",
                "org": org,
                "tool": tool,
                "user_count": users,
                "additional_count": users - 1,
                "first_sighting_date": added.date().isoformat(),
                "event_id": f"patron:shadow_continued:{org}:{tool}:{day}",
            })
        if 72 <= age_h < 24 * 7:
            out.append({
                "kind": "pending72",
                "org": org,
                "tool": tool,
                "user_count": users,
                "event_id": f"patron:shadow_pending72:{org}:{tool}:{day}",
            })
        if age_h >= 24 * 7:
            out.append({
                "kind": "pending7d",
                "org": org,
                "tool": tool,
                "user_count": users,
                "event_id": f"patron:shadow_pending7d:{org}:{tool}:{day}",
            })
    return out


def _load_flags():
    from db.engine import get_session
    from db.models_identity import Org
    from db.models_policy import RavenFlaggedTool
    from sqlalchemy import select

    with get_session() as session:
        rows = session.execute(
            select(RavenFlaggedTool, Org.slug)
            .join(Org, Org.id == RavenFlaggedTool.org_id)
            .where(RavenFlaggedTool.status == "pending")
        ).all()
        flags = []
        for flag, slug in rows:
            flag.org_slug = slug
            flags.append(flag)
        return flags


def _emit_item(item: dict) -> None:
    if item["kind"] == "continued":
        emit_continued_use(
            item["org"], item["event_id"], item["tool"],
            user_count=item["user_count"],
            additional_count=item["additional_count"],
            first_sighting_date=item["first_sighting_date"],
        )
        return
    days = 3 if item["kind"] == "pending72" else 7
    emit_pending_decisions(
        item["org"], item["event_id"], item["user_count"],
        days=days, tool=item["tool"], user_count=item["user_count"],
    )


def run_once(now: datetime | None = None) -> int:
    sent = 0
    for item in due_alerts(_load_flags(), now=now):
        try:
            _emit_item(item)
        except Exception as exc:
            log.warning(
                "shadow_matrix_digest skipped %s %s: %s",
                item.get("kind"), item.get("event_id"), exc,
            )
            continue
        sent += 1
    return sent


def shadow_matrix_digest_loop(stop: threading.Event) -> None:
    """Fire once during PATRON_SHADOW_DIGEST_HOUR (UTC), then wait out the day."""
    log.info("shadow_matrix_digest started (hour=%s UTC)", _HOUR)
    last_day = ""
    while not stop.is_set():
        now = datetime.now(timezone.utc)
        day = now.date().isoformat()
        if now.hour == _HOUR and day != last_day:
            try:
                n = run_once(now)
                last_day = day
                log.info("shadow_matrix_digest sent %s alert(s)", n)
            except Exception as exc:
                log.warning("shadow_matrix_digest failed: %s", exc)
        stop.wait(300)
    log.info("shadow_matrix_digest stopped")
