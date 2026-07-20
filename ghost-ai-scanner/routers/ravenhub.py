# =============================================================
# FILE: routers/ravenhub.py
# VERSION: 1.0.0
# UPDATED: 2026-07-20
# OWNER: Giggso Inc
# PURPOSE: RavenHub router — serves the Exec view's data (KPIs,
#          Data Exposure, Risk Heatmap, AI Landscape, Recent
#          Incidents) as a REST API, so RavenHub can consume it
#          without the FE reading S3 directly.
#          Mirrors, field-for-field, the aggregation logic in:
#            dashboard/ui/data.py            (load_data)
#            dashboard/ui/exec_view.py        (_kpis)
#            dashboard/ui/exec_tab_exposure.py
#            dashboard/ui/exec_tab_risk.py
#            dashboard/ui/exec_tab_landscape.py
#          Read-only. Does not modify or touch the Streamlit UI
#          code path — additive only.
# AUDIT LOG:
#   v1.0.0  2026-07-20  Initial.
# =============================================================

import logging
import os
from collections import defaultdict
from datetime import date, timedelta
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, EmailStr

from blob_index_store import BlobIndexStore

_log = logging.getLogger("patronai.ravenhub")

router = APIRouter()


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
    """Resolve real admin status for `email` the same way the dashboard
    login does: Postgres users table -> S3 users.json -> env allowlist.
    Raises HTTPException(403) if the email isn't recognized anywhere —
    the caller cannot simply assert is_admin, unlike the earlier version
    of this endpoint."""
    db = _db_is_admin(email)
    if db is not None:
        return db
    s3 = _s3_is_admin(email)
    if s3 is not None:
        return s3
    return _env_is_admin(email)


class ExecOverviewResponse(BaseModel):
    email: str
    is_admin: bool
    source_date: Optional[str]
    scoped_event_count: int
    kpis: dict
    data_exposure: dict
    risk_heatmap: dict
    ai_landscape: dict


def _load_events(store: BlobIndexStore, email: str, is_admin: bool) -> tuple:
    """Same walk-back as dashboard/ui/data.py:load_data() — first
    non-empty day in the last 7, capped at 500 findings. Admins get the
    full org-wide event set for that day; non-admins are scoped to
    events owned by (or emailed to) their own address only."""
    summary = store.summary.read() or {}
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    y_summary = store.summary.read(yesterday) or {}

    events: list = []
    source_date: Optional[str] = None
    for days_back in range(0, 8):
        check_date = (date.today() - timedelta(days=days_back)).isoformat()
        df = store.findings.read(check_date, limit=500)
        if not df.is_empty():
            raw_events = df.to_dicts()
            if is_admin:
                events = raw_events
            else:
                em = email.lower()
                events = [
                    e for e in raw_events
                    if (e.get("owner", "") or "").lower() == em
                    or (e.get("email", "") or "").lower() == em
                ]
            source_date = check_date
            break

    return events, summary, y_summary, source_date


def _kpis(events: list, y_summary: dict) -> dict:
    ysev = y_summary.get("by_severity", {})
    findings = [e for e in events if e.get("outcome") == "ENDPOINT_FINDING"]
    high_sev = [e for e in events if e.get("severity") == "HIGH"]
    n_findings = len(findings)
    n_high = len(high_sev)
    n_provs = len(set(e.get("provider", "") for e in events if e.get("provider")))
    n_cats = len(set(e.get("category", "") for e in findings if e.get("category")))

    return {
        "ai_findings": {"value": n_findings, "delta": n_findings - y_summary.get("total_events", 0)},
        "high_severity": {"value": n_high, "delta": n_high - ysev.get("HIGH", 0)},
        "ai_providers_detected": {"value": n_provs, "delta": n_provs - y_summary.get("unique_providers", 0)},
        "categories_found": {"value": n_cats},
        "alerts_fired": {"value": n_findings, "delta": n_findings - y_summary.get("total_events", 0)},
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


@router.get("/exec/overview", response_model=ExecOverviewResponse)
def get_exec_overview(
    email: EmailStr = Query(..., description="Caller's dashboard email"),
) -> ExecOverviewResponse:
    """Exec view content — KPIs, Data Exposure (Sankey + incidents),
    Risk Heatmap (category x severity + top offenders), AI Landscape
    (world map + provider bubble + 30-day trend). Same S3 data and same
    aggregation the Streamlit Exec view renders — computed fresh per
    call, no cache.

    Admin status is resolved server-side from `email` (Postgres users
    table -> S3 users.json -> env allowlist), the same chain
    dashboard/ui/auth_gate.py uses at login. The caller cannot assert
    is_admin — a 403 is raised if the email isn't recognized anywhere."""
    store = _blob_store()
    email_norm = str(email).strip().lower()
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
