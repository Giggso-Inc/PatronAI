# =============================================================
# FILE: routers/ravenhub_settings.py
# VERSION: 1.1.0
# UPDATED: 2026-07-21
# OWNER: Giggso Inc
# PURPOSE: REST export of the Scanning tab — dashboard/ui/tabs/scanning.py.
#          Reads/writes the store.settings JSON blob (via
#          BlobIndexStore.settings — see routers/ravenhub.py's
#          _blob_store).
#          GET  /settings              — scanner/alerts/privacy sections
#                                         of the settings blob, as-is.
#          POST /settings/scanning     — scanner + alerts.dedup_window +
#                                         privacy.hash_emails.
#          Requires the verified X-Raven-Identity JWT, same as every
#          other ravenhub router.
#
#          ADMIN CHECK — TEMP (2026-07-21): same decision as ravenhub.py /
#          ravenhub_projects.py / ravenhub_users.py — the Streamlit tab's
#          admin-only gate lives in the render layer, not inside
#          SettingsStore itself, so there's no internal guard to bypass;
#          any authenticated caller can read/write settings for now.
#          TODO: once FE role routing is integrated, add a real
#          _resolve_is_admin-style check before allowing writes.
#
#          ACCEPTED (PR#9 review round 4, 2026-07-22): unlike the other
#          ravenhub_* routers' TEMP gaps, POST /settings/scanning never
#          had ANY admin check to begin with (not even the relaxed
#          always-True _resolve_is_admin) — any authenticated caller can
#          modify org-wide scan_interval_secs, dedup_window_minutes,
#          max_files_per_cycle, lookback_hours, and the hash_emails
#          privacy toggle. Left as-is: role-based routing (who even
#          reaches this form) is FE work already in the pipeline, not
#          built locally yet — closing this gate here alone, ahead of
#          that FE work landing, wouldn't change who can actually reach
#          it today. Revisit alongside the FE role-routing rollout, not
#          before.
# AUDIT LOG:
#   v1.0.0  2026-07-21  Initial — 4 endpoints (Settings + Scanning).
#   v1.1.0  2026-07-21  Settings (Identity/Alerting) tab removed from
#                       Controls' IA — dropped /settings/identity and
#                       /settings/alerting along with their request models.
#                       Scanning-only now; GET /settings trimmed to the
#                       sections Scanning actually reads.
# =============================================================

import os

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from routers._raven_identity import verify_ravenhub_identity

router = APIRouter(dependencies=[Depends(verify_ravenhub_identity)])


def _store():
    from blob_index_store import BlobIndexStore
    bucket = os.environ.get("MARAUDER_SCAN_BUCKET", "")
    if not bucket:
        raise HTTPException(status_code=503, detail="MARAUDER_SCAN_BUCKET not configured")
    return BlobIndexStore(bucket, os.environ.get("AWS_REGION", "us-east-1"))


class ActionResponse(BaseModel):
    ok: bool
    message: str


class SettingsResponse(BaseModel):
    scanner: dict = {}
    alerts: dict = {}
    privacy: dict = {}


class ScanningRequest(BaseModel):
    scan_interval_secs: int
    dedup_window_minutes: int
    max_files_per_cycle: int
    lookback_hours: int
    hash_emails: bool


def _audit_changes(email: str, old: dict, new: dict) -> None:
    from dashboard.ui import audit as _audit
    _audit.write_batch(email, {k: (old[k], new[k]) for k in old})


@router.get("/settings", response_model=SettingsResponse)
def get_settings_endpoint(email: str = Depends(verify_ravenhub_identity)) -> SettingsResponse:
    """scanner/alerts/privacy sections of the settings blob — the only
    sections the Scanning tab reads."""
    settings = _store().settings.read()
    return SettingsResponse(**{k: settings.get(k, {}) for k in SettingsResponse.model_fields})


@router.post("/settings/scanning", response_model=ActionResponse)
def save_scanning_endpoint(body: ScanningRequest, email: str = Depends(verify_ravenhub_identity)) -> ActionResponse:
    # No admin gate here — see module docstring's "ACCEPTED (PR#9 review
    # round 4)" note. Any authenticated caller can currently write org-wide
    # scan config; closing this is deferred to when FE role routing lands.
    store = _store()
    settings = store.settings.read()
    scanner, alerts, privacy = settings.get("scanner", {}), settings.get("alerts", {}), settings.get("privacy", {})
    old = {
        "scan_interval_secs": scanner.get("scan_interval_secs", 300),
        "dedup_window_minutes": alerts.get("dedup_window_minutes", 60),
        "max_files_per_cycle": scanner.get("max_files_per_cycle", 500),
        "lookback_hours": scanner.get("lookback_hours", 24),
        "hash_emails": privacy.get("hash_emails", False),
    }
    settings.setdefault("scanner", {}).update({
        "scan_interval_secs": body.scan_interval_secs,
        "max_files_per_cycle": body.max_files_per_cycle,
        "lookback_hours": body.lookback_hours,
    })
    settings.setdefault("alerts", {})["dedup_window_minutes"] = body.dedup_window_minutes
    settings.setdefault("privacy", {})["hash_emails"] = body.hash_emails
    new = body.model_dump()
    if not store.settings.write(settings, written_by=email):
        raise HTTPException(status_code=500, detail="Save failed — check tenant storage permissions.")
    _audit_changes(email, old, new)
    return ActionResponse(ok=True, message="Scanning settings saved.")
