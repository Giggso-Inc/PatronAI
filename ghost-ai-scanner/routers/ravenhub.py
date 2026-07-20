# =============================================================
# FILE: routers/ravenhub.py
# VERSION: 1.2.0
# UPDATED: 2026-07-20
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
# NOTE — TRUST BOUNDARY (PR#9 review): every route below takes the
#        caller's identity (`email` / `viewer_email`) as a plain query
#        param and trusts it as-is — `_auth`'s bearer check (api.py)
#        only proves "holds the shared API_KEY", not "is this email".
#        This router does NOT bind the two. Enforcement is required
#        upstream, by both of:
#          - RavenHub's own backend (not browser JS) must derive
#            `email`/`viewer_email` from the caller's authenticated
#            session and inject it server-side — the browser must
#            never be able to set or edit this value.
#          - nginx / network policy must make this API unreachable
#            except from RavenHub's backend (no public route to
#            INTEGRATION_API_PORT). docker-compose*.yml in this repo
#            are dev-only and do not represent that topology.
#        If either control is missing, any holder of API_KEY can
#        assert any email and read/act as that user (or an admin).
#        See PR#9 review note for the accepted-risk writeup.
# AUDIT LOG:
#   v1.0.0  2026-07-20  Initial — /exec/overview.
#   v1.1.0  2026-07-20  Add /inventory/overview (AI Posture + Asset
#                       Inventory, admin-only).
#   v1.2.0  2026-07-20  Document the identity trust boundary (PR#9
#                       review) — FE/session and nginx/network must
#                       enforce caller==email; this router doesn't.
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


# ── Manager view / INVENTORY tab (AI Posture + Asset Inventory) ───────

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


class InventoryOverviewResponse(BaseModel):
    email: str
    is_admin: bool
    message: Optional[str] = None
    source_date: Optional[str] = None
    ai_posture: Optional[dict] = None
    asset_inventory: Optional[list] = None


@router.get("/inventory/overview", response_model=InventoryOverviewResponse)
def get_inventory_overview(
    email: EmailStr = Query(..., description="Caller's dashboard email"),
) -> InventoryOverviewResponse:
    """Manager view's INVENTORY tab — AI Posture (fleet risk score +
    category breakdown) and Asset Inventory (top 20 assets by event
    count), org-wide. Admin-only: a non-admin (or unrecognized) email
    gets 200 OK with is_admin=false and no data, not an error status —
    this endpoint's data is a privilege gate, not an auth failure."""
    email_norm = str(email).strip().lower()
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


# ── Per-user detail page (SCORE + LOGS) ───────────────────────────

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


class UserDetailResponse(BaseModel):
    viewer_email: str
    target_email: str
    authorized: bool
    message: Optional[str] = None
    total_events: Optional[int] = None
    score: Optional[dict] = None
    logs: Optional[list] = None


@router.get("/user/detail", response_model=UserDetailResponse)
def get_user_detail(
    viewer_email: EmailStr = Query(..., description="Caller's own dashboard email"),
    target_email: EmailStr = Query(..., description="Email of the user whose detail page to fetch"),
) -> UserDetailResponse:
    """Per-user detail page — SCORE (per-provider risk breakdown, scored
    with the target's EFFECTIVE policy context) and LOGS (up to 200
    recent events). Mirrors dashboard/ui/user_detail.py's SCORE + LOGS
    tabs (the ASSETS tab is a visual mind-map of the same provider data
    already in `score.providers` — not separately reproduced here).

    Access: admins may view anyone; non-admins may only view themselves
    (viewer_email == target_email). Otherwise 200 OK with authorized=false
    and no data — a privilege gate, not an auth failure. Unlike
    /exec/overview and /inventory/overview, an unresolvable viewer_email
    does not raise 403 here — it's simply treated as non-admin, since
    self-view only needs the viewer/target emails to match."""
    from scoring.breakdown import score_detail

    viewer_norm = str(viewer_email).strip().lower()
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
