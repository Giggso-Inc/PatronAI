# =============================================================
# FILE: routers/ravenhub.py
# VERSION: 1.6.0
# UPDATED: 2026-08-12
# OWNER: Giggso Inc
# PURPOSE: RavenHub router — serves dashboard content as REST APIs so
#          RavenHub can consume it without the FE reading S3 directly.
#          GET /exec/overview      — Exec view (KPIs, Data Exposure,
#                                     Risk Heatmap, AI Landscape).
#          GET /inventory/overview — Manager view's INVENTORY tab
#                                     (AI Posture + Asset Inventory),
#                                     admin-only (non-admin -> 200 with
#                                     is_admin=false, no data).
#          Mirrors, field-for-field, the aggregation logic in:
#            dashboard/ui/data.py               (load_data)
#            dashboard/ui/exec_view.py          (_kpis)
#            dashboard/ui/exec_tab_exposure.py
#            dashboard/ui/exec_tab_risk.py
#            dashboard/ui/exec_tab_landscape.py
#            dashboard/ui/manager_tab_inventory.py
#            dashboard/ui/ai_posture_card.py
#          Read-only. Does not modify or touch the Streamlit UI
#          code path — additive only.
# NOTE — IDENTITY ENFORCEMENT (PR#9 review, C1 — resolved v1.3.0):
#        every route on THIS router requires a verified `X-Raven-Identity`
#        JWT (see _verify_ravenhub_identity below) — issued by
#        raven-enterprise's login/SSO (app/core/auth.py:create_access_token),
#        same secret + HS256. The caller's `email` is read from that
#        verified token, never from a client-supplied query param, so
#        holding the shared API_KEY (api.py's `_auth`, still required
#        unchanged) is no longer sufficient on its own to assert someone
#        else's identity.
#        SCOPE — deliberately limited to this router only. It does NOT
#        apply to api.py's older /agent/status, /score, /agent/report,
#        /score/fleet routes — those are a separate, pre-existing surface
#        with their own (unchanged) email-param pattern, out of scope for
#        this change. This is enforced by declaring the dependency on
#        THIS FILE's `router = APIRouter(...)` only, never on `app` in
#        api.py — so it can never leak onto routes registered elsewhere.
#        Requires RAVEN_JWT_SECRET env var == raven-enterprise's
#        SECRET_KEY (same value, both services). Requires `python-jose`
#        (see requirements.txt) — CVE-check per CLAUDE.md before deploy.
#        ghost-ai-scanner has no centralized settings/config module (no
#        BaseSettings-style class anywhere in this repo) — RAVEN_JWT_SECRET
#        is read inline via os.environ.get(), matching the existing
#        convention (api.py's API_KEY, this file's own MARAUDER_SCAN_BUCKET).
# AUDIT LOG:
#   v1.0.0  2026-07-20  Initial — /exec/overview.
#   v1.1.0  2026-07-20  Add /inventory/overview (AI Posture + Asset
#                       Inventory, admin-only).
#   v1.2.0  2026-07-20  Document the identity trust boundary (PR#9
#                       review) — FE/session and nginx/network must
#                       enforce caller==email; this router doesn't.
#   v1.3.0  2026-07-21  Close the gap documented in v1.2.0: verify a
#                       raven-enterprise-issued JWT (X-Raven-Identity)
#                       and derive caller email from it, router-scoped
#                       only — /exec/overview, /inventory/overview now
#                       take no client email param; /user/detail keeps
#                       target_email (explicit admin-view) but derives
#                       viewer_email from the verified token.
#   v1.4.0  2026-07-21  Reorder file: imports -> response models ->
#                       helper functions -> API routes (no behavior
#                       change).
#   v1.5.0  2026-07-21  _verify_ravenhub_identity extracted to
#                       routers/_raven_identity.py so the new
#                       ravenhub_governance_* routers can share it
#                       instead of duplicating it (no behavior change).
#   v1.6.0  2026-08-12  _kpis() bug fixes: (1) alerts_fired was a
#                       copy-paste of ai_findings (same value/delta) —
#                       now counts ENDPOINT_FINDING/DOMAIN_ALERT/
#                       PORT_ALERT outcomes. (2) ai_findings' delta
#                       compared today's findings against yesterday's
#                       total_events (all outcomes) instead of
#                       yesterday's findings-only count — now uses
#                       y_summary["by_outcome"] symmetrically. Both
#                       are real behavior changes to values returned
#                       by /exec/overview.
# =============================================================

import logging
import os
from collections import defaultdict
from datetime import date, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, EmailStr

from blob_index_store import BlobIndexStore
from routers._raven_identity import verify_ravenhub_identity as _verify_ravenhub_identity

_log = logging.getLogger("patronai.ravenhub")


# =============================================================
# Response models
# =============================================================

class ExecOverviewResponse(BaseModel):
    email: str
    is_admin: bool
    source_date: Optional[str]
    scoped_event_count: int
    kpis: dict
    data_exposure: dict
    risk_heatmap: dict
    ai_landscape: dict


class InventoryOverviewResponse(BaseModel):
    email: str
    is_admin: bool
    message: Optional[str] = None
    source_date: Optional[str] = None
    ai_posture: Optional[dict] = None
    asset_inventory: Optional[list] = None


class ShadowByToolResponse(BaseModel):
    email: str
    is_admin: bool
    message: Optional[str] = None
    source_date: Optional[str] = None
    categories: Optional[list] = None
    total_tools: Optional[int] = None
    total_users: Optional[int] = None
    uncategorised_tools: Optional[int] = None


class UserDetailResponse(BaseModel):
    viewer_email: str
    target_email: str
    authorized: bool
    message: Optional[str] = None
    total_events: Optional[int] = None
    score: Optional[dict] = None
    logs: Optional[list] = None


# =============================================================
# Helper functions
# =============================================================

def _blob_store() -> BlobIndexStore:
    bucket = os.environ.get("MARAUDER_SCAN_BUCKET", "")
    region = os.environ.get("AWS_REGION", "us-east-1")
    if not bucket:
        raise HTTPException(status_code=503, detail="MARAUDER_SCAN_BUCKET not configured")
    return BlobIndexStore(bucket, region)


def _db_is_admin(email: str) -> Optional[bool]:
    """Postgres users table lookup — mirrors dashboard/ui/auth_gate.py's
    _db_resolve(). Returns None (not this user / DB unavailable) so the
    caller can fall through to the next resolver, matching the login
    flow exactly."""
    if not os.environ.get("DATABASE_URL"):
        return None
    try:
        from sqlalchemy import select
        from db.engine import get_session
        from db.models_identity import User
        with get_session() as s:
            u = s.execute(select(User).where(User.email == email)).scalar_one_or_none()
            if u is None:
                return None
            return bool(u.is_org_admin)
    except Exception as exc:                       # noqa: BLE001 — best effort
        _log.warning("RavenHub DB identity resolve failed (falling back to S3/env): %s", exc)
        return None


def _s3_is_admin(email: str) -> Optional[bool]:
    """S3 users.json lookup — mirrors auth_gate.py's _users_store() path.
    Returns None to fall through (store unavailable/empty), or raises
    HTTPException(403) if the store is populated but this email isn't in
    it (an explicit deny, same as auth_gate.py returning role="")."""
    bucket = os.environ.get("MARAUDER_SCAN_BUCKET", "")
    if not bucket:
        return None
    try:
        from store.users_store import UsersStore
        store = UsersStore(bucket, os.environ.get("AWS_REGION", "us-east-1"))
        rec = store.get(email)
        if rec:
            return bool(rec.get("is_admin"))
        if not store.read_all():
            return None
        raise HTTPException(status_code=403, detail="Access denied — email is not on the access list.")
    except HTTPException:
        raise
    except Exception:
        return None


def _env_is_admin(email: str) -> bool:
    """Env-var allowlist — mirrors auth_gate.py's _env_fallback(). Last
    resort; denies (403) if the email is on neither list."""
    admins  = [e.strip().lower() for e in os.environ.get("ADMIN_EMAILS", "").split(",") if e.strip()]
    allowed = [e.strip().lower() for e in os.environ.get("ALLOWED_EMAILS", "").split(",") if e.strip()]
    if email in admins:
        return True
    if email in allowed:
        return False
    raise HTTPException(status_code=403, detail="Access denied — email is not on the access list.")


def _resolve_is_admin(email: str) -> bool:
    """TEMP (2026-07-21): admin/role filtering is deferred to the FE — which
    API to call for an admin/exec/user view isn't wired up there yet. Until
    it is, any email recognized by ANY of Postgres / S3 / env is treated as
    admin (full org-wide data) instead of honoring its real is_admin flag.
    JWT identity verification (_verify_ravenhub_identity) is UNCHANGED and
    still required on every route — this only removes the admin-vs-regular
    distinction for a caller who is already a real, provisioned PatronAI
    user. An email recognized nowhere still gets HTTPException(403) via
    _env_is_admin below, same as before.
    TODO: once FE role-based routing is integrated, go back to honoring the
    real per-source flag (`return db` / `return s3` instead of `return True`)."""
    db = _db_is_admin(email)
    if db is not None:
        return True
    s3 = _s3_is_admin(email)
    if s3 is not None:
        return True
    _env_is_admin(email)  # raises 403 if unrecognized; discard the real flag otherwise
    return True


# A day "has data" only if it has at least one substantive finding — not
# just any row at all. HEARTBEAT/SUPPRESS/CLEAN are non-findings (same set
# _data_exposure() below already excludes as non-"active"); a day with only
# those (e.g. the first few hours of a new day, before any real scan/finding
# events have landed) must not short-circuit the walk-back past a prior
# day's real data.
_NON_SUBSTANTIVE_OUTCOMES = {"HEARTBEAT", "SUPPRESS", "CLEAN"}


def _has_substantive_events(raw_events: list) -> bool:
    return any(e.get("outcome") not in _NON_SUBSTANTIVE_OUTCOMES for e in raw_events)


def _load_events(store: BlobIndexStore, email: str, is_admin: bool) -> tuple:
    """Walk back up to 7 days for the first day with at least one
    substantive finding, capped at 500 findings. Admins get the full
    org-wide event set for that day; non-admins are scoped to events
    owned by (or emailed to) their own address only.

    Deliberately diverges from dashboard/ui/data.py:load_data() here,
    which stops at the first day with ANY rows (including heartbeat-only
    days) — observed live on 2026-07-22: "today" had 2 HEARTBEAT rows and
    nothing else, so the old logic stopped there and never surfaced
    yesterday's 466 rows (152 real ENDPOINT_FINDINGs across 8 providers),
    making Provider Governance's Overview/Newly Found look empty despite
    real data existing one day back. Not touching the Streamlit path
    itself — REST-side fix only, per every ravenhub_* router's own
    "additive only" convention.

    The substantive-events check runs on the CALLER'S OWN slice for a
    non-admin (not the org-wide raw set) — a non-admin's own findings
    could sit a day behind "today"'s org-wide activity even when today
    has plenty of substance from other people (PR#9 review round 2, M1);
    checking the org-wide set would repeat the exact bug this function
    was just fixed for, just one level down, for GET /user/detail.

    y_summary is the day BEFORE the actual source_date found, not a
    hardcoded "yesterday relative to today" (PR#9 review round 3, M1) —
    before this walk-back could skip multiple stale days, source_date
    was virtually always today, so "yesterday" and "day before
    source_date" were the same thing; now that the walk-back can
    genuinely land several days back, _kpis()'s deltas need to compare
    against the day immediately before whatever day was actually used,
    or they silently compare non-adjacent days and mislead the exec KPI
    cards."""
    summary = store.summary.read() or {}

    events: list = []
    source_date: Optional[str] = None
    for days_back in range(0, 8):
        check_date = (date.today() - timedelta(days=days_back)).isoformat()
        df = store.findings.read(check_date, limit=500)
        if not df.is_empty():
            raw_events = df.to_dicts()
            if is_admin:
                candidate = raw_events
            else:
                em = email.lower()
                candidate = [
                    e for e in raw_events
                    if (e.get("owner", "") or "").lower() == em
                    or (e.get("email", "") or "").lower() == em
                ]
            if not _has_substantive_events(candidate):
                continue
            events = candidate
            source_date = check_date
            break

    if source_date:
        prev_day = (date.fromisoformat(source_date) - timedelta(days=1)).isoformat()
        y_summary = store.summary.read(prev_day) or {}
    else:
        y_summary = {}

    return events, summary, y_summary, source_date


def _kpis(events: list, y_summary: dict) -> dict:
    ysev = y_summary.get("by_severity", {})
    yout = y_summary.get("by_outcome", {})
    findings = [e for e in events if e.get("outcome") == "ENDPOINT_FINDING"]
    high_sev = [e for e in events if e.get("severity") == "HIGH"]
    n_findings = len(findings)
    n_high = len(high_sev)
    n_provs = len(set(e.get("provider", "") for e in events if e.get("provider")))
    n_cats = len(set(e.get("category", "") for e in findings if e.get("category")))
    # Same outcome set as ingestor._stats()'s "alerts_fired" (includes
    # ENDPOINT_FINDING, unlike aggregator.aggregate()'s narrower version) —
    # endpoint-only tenants (no DOMAIN_ALERT/PORT_ALERT source configured)
    # would otherwise always read 0 here. Reference side uses the same
    # outcome set from yesterday's by_outcome breakdown, not y_summary's
    # own "alerts_fired" field, since that field is the narrower definition.
    alert_outcomes = ("ENDPOINT_FINDING", "DOMAIN_ALERT", "PORT_ALERT")
    n_alerts = len([e for e in events if e.get("outcome") in alert_outcomes])
    y_alerts = sum(yout.get(o, 0) for o in alert_outcomes)

    return {
        "ai_findings": {"value": n_findings, "delta": n_findings - yout.get("ENDPOINT_FINDING", 0)},
        "high_severity": {"value": n_high, "delta": n_high - ysev.get("HIGH", 0)},
        "ai_providers_detected": {"value": n_provs, "delta": n_provs - y_summary.get("unique_providers", 0)},
        "categories_found": {"value": n_cats},
        "alerts_fired": {"value": n_alerts, "delta": n_alerts - y_alerts},
    }


def _data_exposure(events: list) -> dict:
    active = [e for e in events if e.get("outcome") not in ("SUPPRESS", "HEARTBEAT", "CLEAN")]

    def _src_label(e: dict) -> str:
        return e.get("category") or e.get("department") or "unknown"

    cats_u = [c for c in list(dict.fromkeys(_src_label(e) for e in active)) if c][:8]
    provs_u = [p for p in list(dict.fromkeys(e.get("provider", "") for e in active)) if p][:10]
    node_set = set(cats_u) | set(provs_u)

    links: dict = defaultdict(int)
    for e in active:
        s, p = _src_label(e), e.get("provider", "")
        if s in node_set and p in node_set:
            links[(s, p)] += 1

    sankey = {
        "categories": cats_u,
        "providers": provs_u,
        "links": [{"from": k[0], "to": k[1], "value": v} for k, v in links.items()],
    }

    critical = [e for e in events if e.get("severity") in ("CRITICAL", "HIGH")][:15]
    incidents = [{
        "timestamp": e.get("timestamp"),
        "user": e.get("email") or e.get("owner") or "-",
        "category": e.get("category") or e.get("department") or "-",
        "provider": (e.get("provider") or "-")[:40],
        "severity": e.get("severity", "LOW"),
        "geo_country": e.get("geo_country", ""),
    } for e in critical]

    return {"sankey": sankey, "recent_incidents": incidents}


def _risk_heatmap(events: list) -> dict:
    def _row_label(e: dict) -> str:
        return e.get("category") or e.get("department") or "unknown"

    row_labels = [r for r in sorted(set(_row_label(e) for e in events)) if r]
    sevs = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    matrix = [
        [sum(1 for e in events if _row_label(e) == r and e.get("severity") == s) for s in sevs]
        for r in row_labels
    ]

    by_owner: dict = defaultdict(lambda: {"count": 0, "severity": "LOW", "department": ""})
    for e in events:
        if e.get("outcome") != "SUPPRESS":
            o = e.get("owner", "")
            by_owner[o]["count"] += 1
            by_owner[o]["department"] = e.get("department", "")
            if e.get("severity") == "CRITICAL":
                by_owner[o]["severity"] = "CRITICAL"
            elif e.get("severity") == "HIGH" and by_owner[o]["severity"] != "CRITICAL":
                by_owner[o]["severity"] = "HIGH"
    top_offenders = [
        {"owner": o, **v} for o, v in
        sorted(by_owner.items(), key=lambda x: x[1]["count"], reverse=True)[:10]
    ]

    return {
        "heatmap": {"rows": row_labels, "columns": sevs, "matrix": matrix},
        "top_offenders": top_offenders,
    }


def _ai_landscape(events: list) -> dict:
    by_geo: dict = defaultdict(int)
    for e in events:
        if e.get("geo_country") and e.get("outcome") != "SUPPRESS":
            by_geo[e["geo_country"]] += 1

    by_prov: dict = defaultdict(lambda: {"count": 0, "bytes_out": 0, "severity": "LOW"})
    for e in events:
        if e.get("outcome") != "SUPPRESS":
            p = e.get("provider", "")
            by_prov[p]["count"] += 1
            by_prov[p]["bytes_out"] += e.get("bytes_out", 0) or 0
            if e.get("severity") == "CRITICAL":
                by_prov[p]["severity"] = "CRITICAL"
            elif e.get("severity") == "HIGH" and by_prov[p]["severity"] != "CRITICAL":
                by_prov[p]["severity"] = "HIGH"
    provider_bubble = [
        {"provider": p, **v} for p, v in
        sorted(by_prov.items(), key=lambda x: x[1]["count"], reverse=True)[:10]
    ]

    by_day: dict = defaultdict(int)
    for e in events:
        if e.get("outcome") not in ("SUPPRESS", "HEARTBEAT", "CLEAN"):
            day_key = (e.get("date") or e.get("timestamp", ""))[:10]
            if day_key:
                by_day[day_key] += 1
    dates = sorted(by_day.keys())[-30:]

    return {
        "world_map": dict(by_geo),
        "provider_bubble": provider_bubble,
        "trend_30d": [{"date": d, "count": by_day[d]} for d in dates],
    }


def _org_policy_context():
    """DB-only equivalent of dashboard/ui/policy_context_loader.py's
    load_org_policy_context() — no st.session_state cache (recomputed
    per call), and no CSV fallback (that path reads through a
    Streamlit-coupled provider_lists_io module this API doesn't import).
    Returns None (policy-blind scoring) if DATABASE_URL is unset or the
    lookup fails for any reason — same graceful-degrade contract."""
    if not os.environ.get("DATABASE_URL"):
        return None
    try:
        from sqlalchemy import select
        from db.engine import get_session
        from db.models_identity import Org
        from db.policy_queries import load_policy_context
        slug = os.environ.get("COMPANY_SLUG", "dev")
        with get_session() as s:
            org = (s.execute(select(Org).where(Org.slug == slug)).scalar_one_or_none()
                   or s.execute(select(Org)).scalars().first())
            if org is None:
                return None
            return load_policy_context(s, org_id=org.id)
    except Exception as exc:                       # noqa: BLE001 — best effort
        _log.warning("RavenHub org policy context failed, scoring policy-blind: %s", exc)
        return None


def _user_policy_context(email: str, org_ctx):
    """DB-only equivalent of load_user_policy_context() — effective
    context for one owner (org + their projects + their own list).
    Falls back to `org_ctx` on no DB / unknown user / any error."""
    if not os.environ.get("DATABASE_URL"):
        return org_ctx
    try:
        from sqlalchemy import select
        from db.engine import get_session
        from db.models_identity import Org
        from db.policy_queries import get_identity, load_policy_context
        slug = os.environ.get("COMPANY_SLUG", "dev")
        with get_session() as s:
            user, org_id, project_ids = get_identity(s, email)
            if org_id is None:
                org = (s.execute(select(Org).where(Org.slug == slug)).scalar_one_or_none()
                       or s.execute(select(Org)).scalars().first())
                org_id = org.id if org else None
            if org_id is None:
                return org_ctx
            return load_policy_context(s, org_id=org_id,
                                       user_id=(user.id if user else None),
                                       project_ids=project_ids)
    except Exception as exc:                       # noqa: BLE001 — best effort
        _log.warning("RavenHub user policy context failed for %s, using org: %s", email, exc)
        return org_ctx


def _asset_key(e: dict) -> str:
    """Best identifier for grouping: device_id > src_hostname > src_ip.
    Matches dashboard/ui/manager_tab_inventory.py exactly."""
    return e.get("device_id") or e.get("src_hostname") or e.get("src_ip") or "unknown"


def _owner_of(e: dict) -> str:
    return (e.get("email") or e.get("owner") or "").strip()


# ── Shadow AI by tool ─────────────────────────────────────────────────────────
# Display categories for RavenHub's "Shadow AI By Tools" widget, and the map
# from PatronAI's own detection categories onto them.
#
# WHY THIS LIVES HERE AND NOT IN RAVEN: the Hub's version of this widget reads
# `mcp_governance_notices`, a table that only ever contains MCP servers, and
# recovers a category by substring-matching the tool NAME (checking "MCPs"
# last). Measured against these same findings on 2026-08-17 it misclassified
# 6 of 13 comparable tools — every genuine mcp_server among them, because names
# like `mcp:claude_desktop:weather` match "claude" before they match "mcp", so
# an MCP server is reported as a foundation model. PatronAI does not guess: it
# knows a thing is an MCP server because it read the MCP config, and a browser
# tool because it observed the browser.
#
# "Foundation Models" and "Code Assistant" are deliberately ABSENT. They cannot
# be established from detection evidence — an IDE plugin is observable, but
# whether the model behind it is a foundation model is not — so they were
# dropped rather than guessed. Anything without a confident mapping lands in
# Others; nothing is silently discarded (see `uncategorised_tools`).
_SHADOW_DISPLAY_ORDER = ["MCPs", "Vector DB", "Browser AI", "Others"]

_PATRON_CATEGORY_TO_DISPLAY = {
    "mcp_server": "MCPs",
    "vector_db": "Vector DB",
    "browser": "Browser AI",
    # Real, evidence-backed detections with no dedicated bar of their own.
    # Mapped explicitly rather than left to the default so that a NEW category
    # appearing in the scanner shows up in `uncategorised_tools` instead of
    # quietly inflating Others.
    "ide_plugin": "Others",
    "process": "Others",
    "shell_history": "Others",
    "tool_registration": "Others",
}


def _tool_name_of(e: dict) -> str:
    """Stable identifier for one detected tool. `provider` is the matcher's
    resolved name; dst_domain is the fallback for a network row that matched a
    domain but no named provider."""
    return (e.get("provider") or e.get("dst_domain") or "").strip()


def _shadow_by_tool(events: list) -> dict:
    """Distinct tools and distinct users per display category.

    Counts DISTINCT tool names, not events: one developer hitting one vector DB
    forty times is one tool, not forty. Same for users. This matches what the
    widget's axis claims to show and is why sets are used rather than counters.
    """
    buckets = {c: {"tools": set(), "users": set()} for c in _SHADOW_DISPLAY_ORDER}
    unmapped: set = set()

    for e in events:
        if e.get("status") == "resolved":
            continue
        name = _tool_name_of(e)
        if not name:
            continue
        raw = (e.get("category") or "").strip()
        display = _PATRON_CATEGORY_TO_DISPLAY.get(raw)
        if display is None:
            # An unknown category is a scanner change we have not accounted for.
            # Surface it as Others AND report the count, so a silently-growing
            # Others bar is attributable instead of mysterious.
            display = "Others"
            unmapped.add(name)
        buckets[display]["tools"].add(name)
        owner = _owner_of(e)
        if owner:
            buckets[display]["users"].add(owner)

    categories = [
        {"category": c,
         "tools_count": len(buckets[c]["tools"]),
         "users_count": len(buckets[c]["users"])}
        for c in _SHADOW_DISPLAY_ORDER
    ]
    # Totals are computed over the UNION, not by summing the bars: one tool
    # appearing in two categories, or one developer using tools in three, must
    # count once. Summing the rows would over-report both.
    all_tools = set().union(*(b["tools"] for b in buckets.values()))
    all_users = set().union(*(b["users"] for b in buckets.values()))
    return {
        "categories": categories,
        "total_tools": len(all_tools),
        "total_users": len(all_users),
        "uncategorised_tools": len(unmapped),
    }


def _posture_breakdown_rows(events: list) -> list:
    """Category breakdown rows for the AI Posture card, worst-severity-first
    then highest-count. Extracted from _ai_posture to keep it under the
    50-line style guideline."""
    from scoring.risk_score import posture_breakdown
    bdown = posture_breakdown(events)
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    return sorted(
        (
            {"category": cat, "count": info["count"], "max_severity": info["max_severity"]}
            for cat, info in bdown.items() if info["count"] > 0
        ),
        key=lambda d: (-sev_rank.get(d["max_severity"], 0), -d["count"]),
    )


def _ai_posture(events: list) -> dict:
    """Org-wide AI Posture: per-device score (each scored with its
    owner's EFFECTIVE policy context) -> 60/40 worst-case+avg fleet
    blend, plus the category breakdown. Mirrors
    dashboard/ui/manager_tab_inventory.py:render_inventory() +
    dashboard/ui/ai_posture_card.py:render_ai_posture()."""
    from scoring.risk_score import risk_score, risk_band
    from scoring.breakdown import fleet_blend

    org_ctx = _org_policy_context()
    dev_events: dict = defaultdict(list)
    dev_owner: dict = {}
    for e in events:
        k = _asset_key(e)
        dev_events[k].append(e)
        o = _owner_of(e)
        if o and not dev_owner.get(k):
            dev_owner[k] = o

    ctx_cache: dict = {}

    def _owner_ctx(owner_email: str):
        if not owner_email:
            return org_ctx
        if owner_email not in ctx_cache:
            ctx_cache[owner_email] = _user_policy_context(owner_email, org_ctx)
        return ctx_cache[owner_email]

    dev_score = {k: risk_score(evs, _owner_ctx(dev_owner.get(k, "")))
                 for k, evs in dev_events.items()}
    scores = list(dev_score.values())
    fleet_score = fleet_blend(scores)

    unique_devices = len(dev_events)
    device_label = next(iter(dev_events)) if unique_devices == 1 else f"{unique_devices} devices"
    note = (f"Fleet = 60% x worst device ({max(scores)}) + 40% x avg "
            f"({round(sum(scores) / len(scores))}) across {len(scores)} device(s)"
            if scores else "")

    return {
        "score": fleet_score, "band": risk_band(fleet_score), "device_label": device_label,
        "score_note": note, "breakdown": _posture_breakdown_rows(events), "device_scores": dev_score,
    }


def _asset_inventory(events: list, dev_score: dict, limit: int = 20) -> list:
    """Per-asset rows (top `limit` by event count), mirrors the ASSET
    INVENTORY table in dashboard/ui/manager_tab_inventory.py."""
    from scoring.risk_score import risk_band

    by_asset: dict = defaultdict(lambda: {
        "count": 0, "severity": "CLEAN", "owner": "", "department": "", "mac": "", "type": "",
    })
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "CLEAN": 0}
    for e in events:
        key = _asset_key(e)
        a = by_asset[key]
        a["count"] += 1 if e.get("outcome") != "SUPPRESS" else 0
        new_owner = _owner_of(e)
        if new_owner and (not a["owner"] or e.get("email")):
            a["owner"] = new_owner
        if e.get("department"):
            a["department"] = e["department"]
        if e.get("mac_address"):
            a["mac"] = e["mac_address"]
        if e.get("asset_type"):
            a["type"] = e["asset_type"]
        ev_sev = (e.get("severity") or "CLEAN").upper()
        if sev_rank.get(ev_sev, 0) > sev_rank.get(a["severity"], 0):
            a["severity"] = ev_sev

    ranked = sorted(by_asset.items(), key=lambda x: x[1]["count"], reverse=True)[:limit]
    return [
        {
            "asset_key": key,
            "type": v["type"] or None,
            "owner": v["owner"] or None,
            "department": v["department"] or None,
            "mac": v["mac"] or None,
            "events": v["count"],
            "score": dev_score.get(key, 0),
            "status": risk_band(dev_score.get(key, 0)) if v["count"] > 0 else "CLEAN",
        }
        for key, v in ranked
    ]


def _user_logs(user_events: list, limit: int = 200) -> list:
    """Recent-events rows for one user, mirrors dashboard/ui/user_detail.py
    _render_logs() — newest first, capped at `limit`."""
    rows = sorted(user_events, key=lambda e: e.get("timestamp", ""), reverse=True)[:limit]
    return [
        {
            "timestamp": e.get("timestamp"),
            "device": e.get("src_ip") or e.get("device_id") or None,
            "provider": (e.get("provider") or "")[:60] or None,
            "severity": e.get("severity", "UNKNOWN"),
            "source": (e.get("source") or "")[:30] or None,
            "geo_country": e.get("geo_country") or None,
        }
        for e in rows
    ]


# =============================================================
# API routes
# =============================================================

# `dependencies=` enforces _verify_ravenhub_identity on every route below
# even if a future route forgets to declare the parameter explicitly —
# router-scoped, so it can never apply to routes registered on `app` in
# api.py.
router = APIRouter(dependencies=[Depends(_verify_ravenhub_identity)])


@router.get("/exec/overview", response_model=ExecOverviewResponse)
def get_exec_overview(
    email: str = Depends(_verify_ravenhub_identity),
) -> ExecOverviewResponse:
    """Exec view content — KPIs, Data Exposure (Sankey + incidents),
    Risk Heatmap (category x severity + top offenders), AI Landscape
    (world map + provider bubble + 30-day trend). Same S3 data and same
    aggregation the Streamlit Exec view renders — computed fresh per
    call, no cache.

    `email` is the verified identity from _verify_ravenhub_identity (PR#9
    review, C1) — no longer a client-supplied query param. Admin status is
    then resolved server-side from that verified email (Postgres users
    table -> S3 users.json -> env allowlist), the same chain
    dashboard/ui/auth_gate.py uses at login. The caller cannot assert
    is_admin — a 403 is raised if the email isn't recognized anywhere.

    KNOWN GAP, ACCEPTED (PR#9 review round 4): This endpoint's
    intentional per-user scoping for non-admins ("admins get org-wide
    events, non-admins scoped to their own owner/email only") is
    non-functional: `is_admin` above resolves via _resolve_is_admin,
    which is TEMP-relaxed to always return True (see that function's
    docstring). So _load_events (line 623) always takes the org-wide
    path, and every authenticated caller gets all org events, not just
    their own. Accepted as-is for now: real role-based routing (which
    persona sees this endpoint at all) is FE work already in the
    pipeline, not built yet. Revisit once that FE work lands — this
    endpoint's "scoped to non-admins" claim is aspirational until then,
    not currently enforced."""
    store = _blob_store()
    email_norm = email
    is_admin = _resolve_is_admin(email_norm)

    events, _summary, y_summary, source_date = _load_events(store, email_norm, is_admin)

    return ExecOverviewResponse(
        email=email_norm,
        is_admin=is_admin,
        source_date=source_date,
        scoped_event_count=len(events),
        kpis=_kpis(events, y_summary),
        data_exposure=_data_exposure(events),
        risk_heatmap=_risk_heatmap(events),
        ai_landscape=_ai_landscape(events),
    )


@router.get("/inventory/overview", response_model=InventoryOverviewResponse)
def get_inventory_overview(
    email: str = Depends(_verify_ravenhub_identity),
) -> InventoryOverviewResponse:
    """Manager view's INVENTORY tab — AI Posture (fleet risk score +
    category breakdown) and Asset Inventory (top 20 assets by event
    count), org-wide. Admin-only: a non-admin (or unrecognized) email
    gets 200 OK with is_admin=false and no data, not an error status —
    this endpoint's data is a privilege gate, not an auth failure.

    `email` is the verified identity from _verify_ravenhub_identity
    (PR#9 review, C1) — no longer a client-supplied query param, so this
    admin-only gate can no longer be defeated by simply asserting an
    admin's address.

    KNOWN GAP, ACCEPTED (PR#9 review round 4): `is_admin` below resolves
    via _resolve_is_admin, which is itself TEMP-relaxed to always return
    True for any recognized user (see that function's own docstring) —
    so `if not is_admin` can never fire today and every authenticated
    caller gets org-wide inventory data, not just admins. Accepted as-is
    for now: real role-based routing (which persona sees this endpoint
    at all) is FE work already in the pipeline, not built yet, and this
    is read-only data in a single-org dev environment. Revisit once
    that FE work lands — this docstring's "admin-only" claim is
    aspirational until then, not currently enforced."""
    email_norm = email
    try:
        is_admin = _resolve_is_admin(email_norm)
    except HTTPException:
        return InventoryOverviewResponse(
            email=email_norm, is_admin=False,
            message="Not an admin — no inventory data available.",
        )

    if not is_admin:
        return InventoryOverviewResponse(
            email=email_norm, is_admin=False,
            message="Not an admin — no inventory data available.",
        )

    store = _blob_store()
    events, _summary, _y_summary, source_date = _load_events(store, email_norm, is_admin=True)
    posture = _ai_posture(events)
    dev_score = posture.pop("device_scores")

    return InventoryOverviewResponse(
        email=email_norm,
        is_admin=True,
        source_date=source_date,
        ai_posture=posture,
        asset_inventory=_asset_inventory(events, dev_score),
    )


@router.get("/shadow/by-tool", response_model=ShadowByToolResponse)
def get_shadow_by_tool(
    email: str = Depends(_verify_ravenhub_identity),
) -> ShadowByToolResponse:
    """Shadow AI grouped into display categories, org-wide.

    Replaces RavenHub's own /dashboard-overview/shadow-by-tool, which cannot
    answer this question: it reads `mcp_governance_notices` (MCP servers only)
    and infers a category from the tool's NAME, so its Browser AI bar is
    populated by MCP servers called `claude_browser` / `claude-in-chrome` while
    its MCPs bar reads zero. Here the category comes from how the tool was
    actually detected.

    Admin-gated the same way as /inventory/overview — a non-admin gets 200 with
    is_admin=false and no data, because this is a privilege boundary rather than
    an authentication failure. See that endpoint's docstring for the standing
    caveat that _resolve_is_admin is currently TEMP-relaxed.
    """
    email_norm = email
    try:
        is_admin = _resolve_is_admin(email_norm)
    except HTTPException:
        return ShadowByToolResponse(
            email=email_norm, is_admin=False,
            message="Not an admin — no shadow AI data available.",
        )

    if not is_admin:
        return ShadowByToolResponse(
            email=email_norm, is_admin=False,
            message="Not an admin — no shadow AI data available.",
        )

    store = _blob_store()
    events, _summary, _y_summary, source_date = _load_events(store, email_norm, is_admin=True)
    return ShadowByToolResponse(
        email=email_norm,
        is_admin=True,
        source_date=source_date,
        **_shadow_by_tool(events),
    )


@router.get("/user/detail", response_model=UserDetailResponse)
def get_user_detail(
    target_email: EmailStr = Query(..., description="Email of the user whose detail page to fetch"),
    viewer_email: str = Depends(_verify_ravenhub_identity),
) -> UserDetailResponse:
    """Per-user detail page — SCORE (per-provider risk breakdown, scored
    with the target's EFFECTIVE policy context) and LOGS (up to 200
    recent events). Mirrors dashboard/ui/user_detail.py's SCORE + LOGS
    tabs (the ASSETS tab is a visual mind-map of the same provider data
    already in `score.providers` — not separately reproduced here).

    `viewer_email` is the verified identity from _verify_ravenhub_identity
    (PR#9 review, C1) — the caller can no longer just assert being the
    viewer. `target_email` stays a client-supplied query param on
    purpose: choosing WHICH user's data to look up is the legitimate
    admin-views-someone-else feature this endpoint exists for; only WHO
    is asking needed to stop being self-asserted.

    Access: admins may view anyone; non-admins may only view themselves
    (viewer_email == target_email). Otherwise 200 OK with authorized=false
    and no data — a privilege gate, not an auth failure."""
    from scoring.breakdown import score_detail

    viewer_norm = viewer_email
    target_norm = str(target_email).strip().lower()

    try:
        viewer_is_admin = _resolve_is_admin(viewer_norm)
    except HTTPException:
        viewer_is_admin = False

    if not (viewer_is_admin or viewer_norm == target_norm):
        return UserDetailResponse(
            viewer_email=viewer_norm, target_email=target_norm, authorized=False,
            message="Not authorized to view this user's data.",
        )

    store = _blob_store()
    user_events, _summary, _y_summary, _source_date = _load_events(store, target_norm, is_admin=False)
    policy_ctx = _user_policy_context(target_norm, _org_policy_context())

    return UserDetailResponse(
        viewer_email=viewer_norm, target_email=target_norm, authorized=True,
        total_events=len(user_events),
        score=score_detail(user_events, policy_ctx),
        logs=_user_logs(user_events),
    )
