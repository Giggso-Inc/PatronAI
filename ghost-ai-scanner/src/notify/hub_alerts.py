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
          user: str = "", device: str = "") -> None:
    # Prefer raven_be when cut over; fall back to Hub (which may forward).
    be = (os.environ.get("RAVEN_AUTH_URL") or os.environ.get("RAVEN_BE_URL") or "").rstrip("/")
    hub = (os.environ.get("RAVEN_HUB_URL") or "").rstrip("/")
    if be:
        base, path = be, "/auth/api/v1/alerts/events"
    elif hub:
        base, path = hub, "/api/v1/alerts/events"
    else:
        return
    key = os.environ.get("RAVEN_AGENT_KEY", "")
    try:
        from .hub_licence_gate import note_error, should_skip
    except ImportError:
        from hub_licence_gate import note_error, should_skip  # type: ignore
    if should_skip(base, key):
        return
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
    except Exception as e:
        if note_error(e):
            return
        _log.warning("patron hub emit failed: %s", e)


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
) -> None:
    _emit(
        org, "shadow_ai_continued_use", event_id,
        detail=f"Continued use of shadow tool {tool} ({user_count or len(users or [])} user(s))",
        payload={
            "tool": tool,
            "resource": tool,
            "user_count": user_count or len(users or []),
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


def emit_pending_decisions(org: str, event_id: str, count: int, *, days: int = 3) -> None:
    code = "shadow_ai_pending_7d" if days >= 7 else "shadow_ai_pending_72h"
    label = f">{days} days" if days >= 7 else "72 hrs"
    _emit(org, code, event_id,
          f"{count} shadow AI decisions pending >{label}",
          payload={"count": count, "resource_kind": "shadow_ai",
                   "threshold_days": days, "messaging_event": code})
