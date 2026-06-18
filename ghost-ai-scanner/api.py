# =============================================================
# FILE: api.py
# VERSION: 2.0.0
# UPDATED: 2026-06-18
# OWNER: Giggso Inc
# PURPOSE: Standalone REST API for querying Deploy Agents data
#          and AI-governance posture scoring.
#          POST /agent/status  — deployment status + whitelisted tools by email.
#          GET  /agent/report  — User Risk Report (R3) PDF or HTML.
#          GET  /score         — 7-component posture score for one developer.
#          GET  /score/fleet   — Fleet roll-up: % FAIR, weakest-link, hygiene.
# USAGE:
#   uvicorn api:app --host 0.0.0.0 --port 8002
# ENV:
#   MARAUDER_SCAN_BUCKET  — S3 bucket name (required)
#   AWS_REGION            — AWS region (default: us-east-1)
#   API_KEY               — bearer token for auth (required)
# =============================================================

import csv
import functools
import json
import logging
import os
import secrets
import sys
from datetime import date, datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from fastapi import FastAPI, HTTPException, Depends, Security, Query, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr

from store.agent_store import AgentStore
from blob_index_store import BlobIndexStore  # noqa: E402
from dashboard.ui.reports import r3_user  # noqa: E402
from dashboard.ui.reports._logo import fetch_logo_b64  # noqa: E402
from dashboard.ui.reports._pdf import html_to_pdf  # noqa: E402
from agent_package_store import AgentPackageStore
from scoring.posture_score import (
    build_approved_set,
    compute_user_score,
    is_approved_provider,
)

app = FastAPI(
    title="PatronAI API",
    description="Deploy Agents status, user risk reports, and AI-governance posture scores.",
    version="2.0.0",
)

_bearer  = HTTPBearer(auto_error=False)
_API_KEY = os.environ.get("API_KEY", "")
if not _API_KEY:
    raise RuntimeError(
        "API_KEY environment variable is not set. "
        "Endpoints expose PII — refusing to start without authentication. "
        "Set API_KEY to a strong random secret before running."
    )

_CONFIG_DIR = os.path.join(os.path.dirname(__file__), "config")


# ── Auth / store helpers ──────────────────────────────────────

def _auth(creds: HTTPAuthorizationCredentials | None = Security(_bearer)) -> None:
    if creds is None or not secrets.compare_digest(creds.credentials, _API_KEY):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def _get_store() -> AgentStore:
    bucket = os.environ.get("MARAUDER_SCAN_BUCKET", "")
    if not bucket:
        raise HTTPException(status_code=503, detail="MARAUDER_SCAN_BUCKET not configured")
    region = os.environ.get("AWS_REGION", "us-east-1")
    return AgentStore(bucket, region)


def _blob_store() -> BlobIndexStore:
    bucket = os.environ.get("MARAUDER_SCAN_BUCKET", "")
    region = os.environ.get("AWS_REGION", "us-east-1")
    if not bucket:
        raise HTTPException(status_code=503, detail="MARAUDER_SCAN_BUCKET not configured")
    return BlobIndexStore(bucket, region)


# ── CSV loaders (disk) ────────────────────────────────────────

@functools.lru_cache(maxsize=None)
def _load_authorized_csv(filename: str) -> list[dict]:
    """Load an authorized-list CSV, skipping blank lines and comment rows."""
    path = os.path.join(_CONFIG_DIR, filename)
    rows: list[dict] = []
    try:
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                first = next(iter(row.values()), "").strip()
                if not first or first.startswith("#"):
                    continue
                rows.append({k.strip(): v.strip() for k, v in row.items()})
    except FileNotFoundError:
        logger.warning("Authorized CSV not found: %s", path)
    except Exception as exc:
        logger.error("Failed to load %s: %s", path, exc)
    return rows


# ── S3 helpers ────────────────────────────────────────────────

def _read_heartbeat(store: BlobIndexStore, token: str) -> Optional[dict]:
    """Fetch the latest heartbeat JSON for a given agent token. Returns None if absent."""
    raw = store.agent._get(f"ocsf/agent/heartbeats/{token}/latest.json")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception as exc:
        logger.warning("Heartbeat parse failed [%s...]: %s", token[:8], exc)
        return None


def _freshest_heartbeat(store: BlobIndexStore, tokens: list) -> Optional[dict]:
    """Return the heartbeat with the most recent timestamp across all tokens.
    Any fresh agent wins — catalog ordering is not authoritative."""
    best: Optional[dict] = None
    best_ts = ""
    for token in tokens:
        hb = _read_heartbeat(store, token)
        if hb is None:
            continue
        ts = hb.get("timestamp") or hb.get("time") or ""
        if best is None or ts > best_ts:
            best, best_ts = hb, ts
    return best


def _list_finding_dates(store: BlobIndexStore, d_from: str, d_to: str) -> list[str]:
    """Return sorted list of finding dates (YYYY-MM-DD) in [d_from, d_to]."""
    try:
        paginator = store.findings.s3.get_paginator("list_objects_v2")
        dates: set = set()
        for page in paginator.paginate(Bucket=store.bucket, Prefix="findings/"):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if not key.endswith(".jsonl"):
                    continue
                parts = key.split("/")
                if len(parts) >= 5:
                    dt = f"{parts[1]}-{parts[2]}-{parts[3]}"
                    if d_from <= dt <= d_to:
                        dates.add(dt)
        return sorted(dates)
    except Exception as exc:
        logger.error("Failed to list findings dates: %s", exc)
        return []


def _fetch_all_events(store: BlobIndexStore, dates: list[str]) -> list[dict]:
    """Read all finding events across the given dates (no owner filter).
    Events per date are capped at 2 000 to protect memory on large fleets."""
    events: list = []
    for dt in dates:
        try:
            df = store.findings.read(dt, limit=2000)
            if not df.is_empty():
                events.extend(df.to_dicts())
        except Exception as exc:
            logger.warning("Failed to read findings for date %s: %s", dt, exc)
    return events


def _filter_user_events(all_events: list, email: str) -> list:
    """Post-filter org events to those belonging to a single user.
    Checks both the 'owner' and 'email' fields for compatibility with
    older event formats that used 'email' as the primary key."""
    em = email.lower()
    return [
        e for e in all_events
        if (e.get("owner") or "").lower() == em
        or (e.get("email") or "").lower() == em
    ]


def _default_dates(d_from: Optional[str], d_to: Optional[str]) -> tuple[str, str]:
    today = datetime.now(timezone.utc).date()
    return (
        d_from or (today - timedelta(days=30)).isoformat(),
        d_to   or today.isoformat(),
    )


# ── Request / Response models ─────────────────────────────────

class StatusRequest(BaseModel):
    email: str


class DeploymentRecord(BaseModel):
    name: str
    email: str
    platform: str
    status: str
    created: str
    whitelisted_tools: list[str]


class StatusResponse(BaseModel):
    email: str
    deployments: list[DeploymentRecord]


class ComponentScore(BaseModel):
    weight: int
    earned: int
    detail: dict


class ScoreResponse(BaseModel):
    email: str
    period: dict
    score: int
    band: str
    components: dict[str, ComponentScore]
    improvements: list[dict]


class FleetUserSummary(BaseModel):
    email: str
    score: int
    band: str


class FleetMetrics(BaseModel):
    total_users: int
    users_at_or_above_fair: int
    pct_at_or_above_fair: float
    weakest_link_score: int
    weakest_link_email: str
    authorised_tools_hygiene: float


class FleetResponse(BaseModel):
    period: dict
    fleet: FleetMetrics
    user_scores: list[FleetUserSummary]


# ── Endpoints: agent ──────────────────────────────────────────

@app.post("/agent/status", response_model=StatusResponse)
def get_agent_status(
    body: StatusRequest,
    _: None = Depends(_auth),
) -> StatusResponse:
    """
    Return deployment status and whitelisted tools for a given email.
    Matches all packages in the catalog where recipient_email equals the
    supplied email (case-insensitive). Returns an empty deployments list
    if no packages are found — 404 only when S3 is unreachable.
    """
    store = _get_store()
    lookup = body.email.strip().lower()

    try:
        catalog = store.refresh_statuses(store.list_catalog())
    except Exception as exc:
        logger.error("Could not read catalog: %s", exc, exc_info=True)
        raise HTTPException(status_code=502, detail="Could not read catalog") from exc

    matched: list[DeploymentRecord] = []
    for entry in catalog:
        if entry.get("recipient_email", "").strip().lower() != lookup:
            continue

        token = entry.get("token", "")
        try:
            domains = store.get_authorized_domains(token)
        except Exception:
            domains = entry.get("authorized_domains", [])

        matched.append(DeploymentRecord(
            name=entry.get("recipient_name", ""),
            email=entry.get("recipient_email", ""),
            platform=entry.get("os_type", ""),
            status=entry.get("status", "pending"),
            created=entry.get("created_at", ""),
            whitelisted_tools=domains,
        ))

    return StatusResponse(email=body.email, deployments=matched)


@app.get("/agent/report")
def user_report(
    email: EmailStr = Query(..., description="Recipient email for the user risk report"),
    d_from: Optional[str] = Query(None, description="Start date (YYYY-MM-DD), defaults to 30 days ago"),
    d_to: Optional[str] = Query(None, description="End date (YYYY-MM-DD), defaults to today"),
    format: str = Query("pdf", description="Output format: 'pdf' or 'html'"),
    _: None = Depends(_auth),
) -> Response:
    """
    Generate and return the User Risk Report (R3) for the given email.
    Supports returning either PDF (default) or HTML.
    """
    if format.lower() not in ("pdf", "html"):
        raise HTTPException(
            status_code=400,
            detail="Invalid format. Supported formats are 'pdf' or 'html'."
        )

    d_from, d_to = _default_dates(d_from, d_to)
    store = _blob_store()

    try:
        paginator = store.findings.s3.get_paginator("list_objects_v2")
        keys_to_read = []
        for page in paginator.paginate(Bucket=store.bucket, Prefix="findings/"):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if not key.endswith(".jsonl"):
                    continue
                parts = key.split("/")
                if len(parts) >= 5:
                    date_str = f"{parts[1]}-{parts[2]}-{parts[3]}"
                    if d_from <= date_str <= d_to:
                        keys_to_read.append(date_str)
    except Exception as exc:
        logger.error("Failed to list findings from S3: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to list findings")

    unique_dates = sorted(set(keys_to_read))

    events = []
    for dt in unique_dates:
        try:
            df = store.findings.read(dt, limit=1000)
            if not df.is_empty():
                events.extend(df.to_dicts())
        except Exception:
            pass

    company = os.environ.get("COMPANY_NAME", "PatronAI")
    logo_b64 = fetch_logo_b64(store.bucket, store.region)

    try:
        html_str = r3_user.build_html(
            events=events,
            d_from=d_from,
            d_to=d_to,
            admin_email=str(email),
            company=company,
            logo_b64=logo_b64,
            target_email=str(email),
        )
    except Exception as exc:
        logger.error("Failed to build report HTML: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to build report")

    if format.lower() == "pdf":
        try:
            pdf_bytes = html_to_pdf(html_str)
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=user_report_{email}.pdf"},
            )
        except Exception as exc:
            logger.error("Failed to generate report PDF: %s", exc, exc_info=True)
            raise HTTPException(status_code=500, detail="Failed to generate report PDF")

    return Response(content=html_str, media_type="text/html")


# ── Endpoints: scoring ────────────────────────────────────────

@app.get("/agent/score", response_model=ScoreResponse)
def get_score(
    email: EmailStr = Query(..., description="Developer email to score"),
    d_from: Optional[str] = Query(None, description="Start date YYYY-MM-DD (default: 30 days ago)"),
    d_to:   Optional[str] = Query(None, description="End date YYYY-MM-DD (default: today)"),
    _: None = Depends(_auth),
) -> ScoreResponse:
    """
    Compute the 7-component AI-governance posture score (0-100) for one developer.

    Components and weights:
      approved_tools (30)    All AI tools on the approved list.
      no_ghost_assets (20)   No abandoned assets > 30 days old.
      mcp_hygiene (20)       MCP servers registered and scope-bounded.
      no_high_findings (10)  No open HIGH or CRITICAL findings in period.
      domain_compliance (10) Authorised domains actually in use.
      provider_count (5)     Unique providers within 1.5× org average.
      identity_binding (5)   device_uuid + valid MAC + fresh heartbeat.
    """
    d_from, d_to = _default_dates(d_from, d_to)
    store        = _blob_store()
    email_lower  = str(email).strip().lower()

    auth_csv      = _load_authorized_csv("authorized.csv")
    auth_code_csv = _load_authorized_csv("authorized_code.csv")

    catalog      = store.agent.list_catalog()
    user_entries = [e for e in catalog
                    if (e.get("recipient_email") or "").lower() == email_lower]
    per_user_domains: list = []
    user_tokens: list = []
    for entry in user_entries:
        per_user_domains.extend(entry.get("authorized_domains") or [])
        if entry.get("token"):
            user_tokens.append(entry["token"])

    approved_set = build_approved_set(auth_csv, auth_code_csv, list(set(per_user_domains)))

    dates      = _list_finding_dates(store, d_from, d_to)
    org_events = _fetch_all_events(store, dates)
    user_events = _filter_user_events(org_events, email_lower)

    # Pick the freshest heartbeat across all agent tokens so a user with multiple
    # devices (e.g. mac + windows) is not failed because the first catalog entry
    # happens to be stale.
    heartbeat = _freshest_heartbeat(store, user_tokens)

    result = compute_user_score(
        user_events=user_events,
        org_events=org_events,
        approved_set=approved_set,
        authorized_domains=list(set(per_user_domains)),
        heartbeat=heartbeat,
        period_end=d_to,
    )

    return ScoreResponse(
        email=email_lower,
        period={"from": d_from, "to": d_to},
        score=result["score"],
        band=result["band"],
        components={k: ComponentScore(**v) for k, v in result["components"].items()},
        improvements=result["improvements"],
    )


@app.get("/agent/score/fleet", response_model=FleetResponse)
def get_fleet_score(
    d_from: Optional[str] = Query(None, description="Start date YYYY-MM-DD (default: 30 days ago)"),
    d_to:   Optional[str] = Query(None, description="End date YYYY-MM-DD (default: today)"),
    _: None = Depends(_auth),
) -> FleetResponse:
    """
    Fleet roll-up across all provisioned developers.

    Returns:
      pct_at_or_above_fair        — % of fleet scoring ≥ 65 (FAIR or better).
      weakest_link_score/email    — lowest-scored developer (blast-radius metric).
      authorised_tools_hygiene    — Σ events from approved providers / Σ all events.
      user_scores                 — per-developer (email, score, band), sorted low-first.

    NOTE: One S3 heartbeat read per catalog user. On large fleets (> 200 users)
    consider pre-warming heartbeat data or running this as an async background job.
    """
    d_from, d_to = _default_dates(d_from, d_to)
    store = _blob_store()

    auth_csv      = _load_authorized_csv("authorized.csv")
    auth_code_csv = _load_authorized_csv("authorized_code.csv")

    catalog = store.agent.list_catalog()
    user_map: dict[str, dict] = {}
    for entry in catalog:
        em = (entry.get("recipient_email") or "").strip().lower()
        if em:
            user_map[em] = entry

    dates      = _list_finding_dates(store, d_from, d_to)
    org_events = _fetch_all_events(store, dates)

    user_event_map: dict[str, list] = {}
    for e in org_events:
        u = (e.get("owner") or e.get("email") or "").lower()
        if u:
            user_event_map.setdefault(u, []).append(e)

    user_scores: list[dict] = []
    for email_lower, entry in user_map.items():
        token            = entry.get("token")
        per_user_domains = entry.get("authorized_domains") or []
        approved_set     = build_approved_set(auth_csv, auth_code_csv, per_user_domains)
        heartbeat        = _read_heartbeat(store, token) if token else None
        u_events         = user_event_map.get(email_lower, [])

        result = compute_user_score(
            user_events=u_events,
            org_events=org_events,
            approved_set=approved_set,
            authorized_domains=per_user_domains,
            heartbeat=heartbeat,
            period_end=d_to,
        )
        user_scores.append({
            "email": email_lower,
            "score": result["score"],
            "band":  result["band"],
        })

    total      = len(user_scores)
    above_fair = [u for u in user_scores if u["score"] >= 65]
    pct_fair   = round(len(above_fair) / total * 100, 1) if total else 0.0
    weakest    = min(user_scores, key=lambda u: u["score"]) if user_scores else {}

    global_approved = build_approved_set(auth_csv, auth_code_csv, [])
    finding_evts    = [e for e in org_events if e.get("outcome") == "ENDPOINT_FINDING"]
    approved_evts   = [e for e in finding_evts
                       if is_approved_provider(e.get("provider") or "", global_approved)]
    hygiene = round(len(approved_evts) / len(finding_evts), 3) if finding_evts else 0.0

    user_scores.sort(key=lambda u: u["score"])

    return FleetResponse(
        period={"from": d_from, "to": d_to},
        fleet=FleetMetrics(
            total_users=total,
            users_at_or_above_fair=len(above_fair),
            pct_at_or_above_fair=pct_fair,
            weakest_link_score=weakest.get("score", 0),
            weakest_link_email=weakest.get("email", ""),
            authorised_tools_hygiene=hygiene,
        ),
        user_scores=[FleetUserSummary(**u) for u in user_scores],
    )


# ── Health ────────────────────────────────────────────────────

@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}
