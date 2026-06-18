# =============================================================
# FILE: score_api.py
# VERSION: 1.0.0
# UPDATED: 2026-06-18
# OWNER: Giggso Inc
# PURPOSE: REST API for AI-governance posture scoring.
#          GET /score       — 7-component score for one developer (0-100).
#          GET /score/fleet — Fleet roll-up: % FAIR, weakest-link, hygiene.
# USAGE:
#   uvicorn score_api:app --host 0.0.0.0 --port 8003
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

from fastapi import FastAPI, HTTPException, Depends, Security, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr

from blob_index_store import BlobIndexStore
from scoring.posture_score import (
    build_approved_set,
    compute_user_score,
    is_approved_provider,
)

app = FastAPI(
    title="PatronAI Posture Score API",
    description="AI-governance posture scores (0-100) per developer and fleet.",
    version="1.0.0",
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


# ── Auth / store helpers ──────────────────────────────────────────────────────

def _auth(creds: HTTPAuthorizationCredentials | None = Security(_bearer)) -> None:
    if creds is None or not secrets.compare_digest(creds.credentials, _API_KEY):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def _blob_store() -> BlobIndexStore:
    bucket = os.environ.get("MARAUDER_SCAN_BUCKET", "")
    region = os.environ.get("AWS_REGION", "us-east-1")
    if not bucket:
        raise HTTPException(status_code=503, detail="MARAUDER_SCAN_BUCKET not configured")
    return BlobIndexStore(bucket, region)


# ── CSV loaders (disk) ────────────────────────────────────────────────────────

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


# ── S3 helpers ────────────────────────────────────────────────────────────────

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


# ── Response models ───────────────────────────────────────────────────────────

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


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/score", response_model=ScoreResponse)
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
    store       = _blob_store()
    email_lower = str(email).strip().lower()

    # 1. Authorized lists from disk
    auth_csv      = _load_authorized_csv("authorized.csv")
    auth_code_csv = _load_authorized_csv("authorized_code.csv")

    # 2. Per-user authorized domains + agent token from catalog
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

    # 3. Fetch all org events for the period (single pass; reused for org average)
    dates      = _list_finding_dates(store, d_from, d_to)
    org_events = _fetch_all_events(store, dates)

    # 4. Filter to this user's events
    user_events = _filter_user_events(org_events, email_lower)

    # 5. Heartbeat (identity binding) — pick the freshest across all agent tokens so
    #    a user with multiple devices (e.g. mac + windows) is not failed because the
    #    first catalog entry happens to be stale.
    heartbeat = _freshest_heartbeat(store, user_tokens)

    # 6. Compute score
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


@app.get("/score/fleet", response_model=FleetResponse)
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

    # Unique email → catalog entry (latest entry wins if duplicate emails exist)
    catalog = store.agent.list_catalog()
    user_map: dict[str, dict] = {}
    for entry in catalog:
        em = (entry.get("recipient_email") or "").strip().lower()
        if em:
            user_map[em] = entry

    # Fetch all org events once; split by user in memory
    dates      = _list_finding_dates(store, d_from, d_to)
    org_events = _fetch_all_events(store, dates)

    user_event_map: dict[str, list] = {}
    for e in org_events:
        u = (e.get("owner") or e.get("email") or "").lower()
        if u:
            user_event_map.setdefault(u, []).append(e)

    # Score each user
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

    total       = len(user_scores)
    above_fair  = [u for u in user_scores if u["score"] >= 65]
    pct_fair    = round(len(above_fair) / total * 100, 1) if total else 0.0
    weakest     = min(user_scores, key=lambda u: u["score"]) if user_scores else {}

    # Fleet authorised-tools hygiene: org-level approved set (no per-user domains)
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


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}
