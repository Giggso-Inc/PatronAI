"""Emit PatronAI shadow/deny alerts to Raven Hub (taxonomy V2)."""

from __future__ import annotations

import json
import logging
import os
import urllib.request

_log = logging.getLogger(__name__)


def _infer_kind(tool: str, outcome: str = "") -> str:
    low = (tool or "").lower()
    oc = (outcome or "").upper()
    if "mcp" in low:
        return "mcp"
    if oc == "DOMAIN_ALERT" or ("." in low and " " not in low and "/" not in low):
        return "domain"
    if oc in ("CODE_ALERT", "UNKNOWN"):
        return "shadow_ai"
    if oc in ("PORT_ALERT", "PERSONAL_KEY"):
        return "denylist"
    return "other"


def _emit(org: str, code: str, event_id: str, detail: str = "",
          payload: dict | None = None,
          user: str = "", device: str = "") -> bool:
    # Prefer raven_be when cut over; fall back to Hub (which may forward).
    be = (os.environ.get("RAVEN_AUTH_URL") or os.environ.get("RAVEN_BE_URL") or "").rstrip("/")
    hub = (os.environ.get("RAVEN_HUB_URL") or "").rstrip("/")
    if be:
        base, path = be, "/auth/api/v1/alerts/events"
    elif hub:
        base, path = hub, "/api/v1/alerts/events"
    else:
        return False
    key = os.environ.get("RAVEN_AGENT_KEY", "")
    try:
        from .hub_licence_gate import note_error, should_skip
    except ImportError:
        from hub_licence_gate import note_error, should_skip  # type: ignore
    if should_skip(base, key):
        return False
    pl = dict(payload or {})
    if user:
        pl.setdefault("user", user)
        pl.setdefault("owner", user)
    if device:
        pl.setdefault("device", device)
        pl.setdefault("src_ip", device)
    body = {
        "org": org, "alert_code": code, "source_event_id": event_id,
        "detail": detail, "source_product": "patron", "payload": pl,
        "actor_user": user, "actor_device": device,
        "user": user, "src_ip": device,
        "resource": pl.get("resource") or pl.get("tool") or "",
        "resource_kind": pl.get("resource_kind") or "",
    }
    try:
        req = urllib.request.Request(
            f"{base}{path}",
            data=json.dumps(body).encode(), method="POST",
            headers={"Content-Type": "application/json",
                     **({"X-Raven-Agent": key} if key else {})},
        )
        urllib.request.urlopen(req, timeout=8)
        return True
    except Exception as e:
        if note_error(e):
            return False
        _log.warning("patron hub emit failed: %s", e)
        return False


def emit_shadow_discovered(
    org: str, event_id: str, tool: str,
    user: str = "", device: str = "",
    outcome: str = "", domain: str = "", hostname: str = "",
) -> None:
    kind = _infer_kind(tool, outcome or "UNKNOWN")
    _emit(
        org, "shadow_ai_discovered", event_id,
        detail=f"New {kind}: {tool}",
        payload={
            "tool": tool,
            "resource": tool,
            "resource_kind": kind,
            "tool_kind": kind,
            "outcome": outcome or "UNKNOWN",
            "domain": domain or tool,
            "hostname": hostname or device,
        },
        user=user, device=device or hostname,
    )


def emit_user_first_use(
    org: str, event_id: str, tool: str,
    user: str = "", device: str = "",
    outcome: str = "", domain: str = "", hostname: str = "",
) -> None:
    """Email the workforce user on first sighting of a shadow tool for them."""
    kind = _infer_kind(tool, outcome or "UNKNOWN")
    _emit(
        org, "shadow_ai_user_first_use", event_id,
        detail=f"First use of shadow tool {tool} by {user or 'user'}",
        payload={
            "tool": tool,
            "resource": tool,
            "resource_kind": kind,
            "tool_kind": kind,
            "outcome": outcome or "UNKNOWN",
            "domain": domain or tool,
            "hostname": hostname or device,
            "messaging_event": "shadow_ai_user_first_use",
        },
        user=user, device=device or hostname,
    )


def emit_continued_use(
    org: str, event_id: str, tool: str, *,
    user_count: int = 0, users: list | None = None,
    additional_count: int | None = None,
    first_sighting_date: str = "",
) -> None:
    """Daily aggregate for the sheet row 'more users continue to use the shadow tool'."""
    total = user_count or len(users or [])
    extra = additional_count if additional_count is not None else max(total - 1, 0)
    _emit(
        org, "shadow_ai_continued_use", event_id,
        detail=f"Continued use of shadow tool {tool} ({total} user(s))",
        payload={
            "tool": tool,
            "tool_name": tool,
            "resource": tool,
            "user_count": total,
            "additional_count": extra,
            "total_count": total,
            "first_sighting_date": first_sighting_date,
            "users": list(users or []),
            "messaging_event": "shadow_ai_continued_use",
        },
    )


def emit_denylisted(
    org: str, event_id: str, tool: str,
    user: str = "", device: str = "",
    outcome: str = "", domain: str = "", hostname: str = "",
) -> None:
    kind = _infer_kind(tool, outcome or "DOMAIN_ALERT")
    _emit(
        org, "denylisted_ai_tool", event_id,
        detail=f"Denylisted {kind}: {tool}",
        payload={
            "tool": tool,
            "resource": tool,
            "resource_kind": kind,
            "tool_kind": kind,
            "outcome": outcome or "DOMAIN_ALERT",
            "domain": domain or tool,
            "hostname": hostname or device,
        },
        user=user, device=device or hostname,
    )


def emit_pending_decisions(
    org: str, event_id: str, count: int, *,
    days: int = 3, tool: str = "", user_count: int | None = None,
) -> None:
    """Sheet rows: decision pending more than 72 hours, and more than 7 days."""
    code = "shadow_ai_pending_7d" if days >= 7 else "shadow_ai_pending_72h"
    label = f">{days} days" if days >= 7 else "72 hrs"
    users = user_count if user_count is not None else count
    _emit(org, code, event_id,
          f"{tool or 'Shadow tool'} decision pending >{label} ({users} user(s))",
          payload={
              "count": count,
              "user_count": users,
              "tool": tool,
              "tool_name": tool,
              "resource": tool,
              "resource_kind": "shadow_ai",
              "threshold_days": days,
              "messaging_event": code,
          })


def emit_tamper(
    org: str, event_id: str, detail: str = "",
    payload: dict | None = None,
    user: str = "", device: str = "",
) -> bool:
    """Integrity failure on Patron agent files/folders (admins + developer)."""
    from datetime import datetime, timezone

    pl = dict(payload or {})
    pl.setdefault("messaging_event", "patron_tamper")
    # Action-specific product event so matrix picks modified/deleted/added/base_fail.
    et = str(pl.get("event_type") or "").strip().upper()
    if et:
        suffix = {
            "MODIFIED": "modified",
            "DELETED": "deleted",
            "ADDED": "added",
            "BASE_FAIL": "base_fail",
            "WATCH_DIE": "watch_die",
        }.get(et, "modified")
        pl["messaging_event"] = f"patron_tamper_{suffix}"
    pl.setdefault("resource", pl.get("file_path") or detail or "tamper")
    pl.setdefault("resource_kind", "antitamper")
    if user:
        pl.setdefault("user", user)
        pl.setdefault("user_email", user)
    pl.setdefault(
        "timestamp",
        datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
    return _emit(org, "patron_tamper", event_id, detail or "Patron agent tamper",
                 payload=pl, user=user, device=device)
