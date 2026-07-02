# =============================================================
# FILE: dashboard/ui/policy_context_loader.py
# VERSION: 2.0.0
# UPDATED: 2026-06-30
# OWNER: Giggso Inc
# PURPOSE: Resolve a PolicyContext for the AI-Posture score.
#          - DB mode (DATABASE_URL set): auto-seed the policy DB from S3
#            once, then read org-scope policy from Postgres (ADR_2026-06-29).
#          - CSV mode (no DB): read the S3 CSV lists directly (Phase A).
#          Degrades gracefully to CSV / None on any failure (R3) — a policy
#          read must never crash the dashboard.
# DEPENDS: streamlit, scoring.*, db.* (when DATABASE_URL set), provider_lists_io
# AUDIT LOG:
#   v1.0.0  2026-06-29  CSV-backed org context (Phase A).
#   v2.0.0  2026-06-30  DB-backed org context + one-time S3->DB seed (F1/F3).
# =============================================================

import json
import logging
import os
import sys

import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from scoring.policy import PolicyContext            # noqa: E402
from scoring.policy_resolver import context_from_csv  # noqa: E402
from .tabs import provider_lists_io as _io           # noqa: E402

log = logging.getLogger("patronai.ui.policy_context_loader")

_CACHE = "policy_ctx_org"
_SEEDED = "db_seeded"

# S3 config keys -> expected columns.
_ALLOW       = ("config/authorized.csv", ["name", "domain_pattern", "notes"])
_ALLOW_CODE  = ("config/authorized_code.csv", ["name", "type", "pattern", "dept_scope", "notes"])
_DENY_CUSTOM = ("config/unauthorized_custom.csv", ["name", "category", "domain", "port", "severity", "notes"])
_DENY_CODE   = ("config/unauthorized_code_custom.csv", ["name", "type", "pattern", "severity", "notes"])
_BASELINE    = ("config/unauthorized.csv", ["name", "category", "domain", "port", "severity", "notes"])


def _rows(key_cols):
    key, cols = key_cols
    return _io.read_csv_df(key, cols).to_dict("records")


def _csv_context():
    """Org-scope PolicyContext straight from the S3 CSVs (no DB)."""
    return context_from_csv(
        authorized=_rows(_ALLOW), authorized_code=_rows(_ALLOW_CODE),
        unauthorized_custom=_rows(_DENY_CUSTOM),
        unauthorized_code_custom=_rows(_DENY_CODE),
        giggso_baseline=_rows(_BASELINE),
    )


def _read_users_json() -> dict:
    """Read users/users.json from S3 (for the one-time seed)."""
    try:
        import boto3
        bucket = os.environ.get("MARAUDER_SCAN_BUCKET", "")
        region = os.environ.get("AWS_REGION", "us-east-1")
        body = boto3.client("s3", region_name=region).get_object(
            Bucket=bucket, Key="users/users.json")["Body"].read().decode()
        return json.loads(body)
    except Exception:
        return {}


def _ensure_seeded(session) -> None:
    """One-time S3 -> DB seed (idempotent; guarded by session_state + DB marker)."""
    if st.session_state.get(_SEEDED):
        return
    from db.seeding import seed_all
    seed_all(
        session,
        org_slug=os.environ.get("COMPANY_SLUG", "dev"),
        org_name=os.environ.get("COMPANY_NAME", "PatronAI"),
        bucket=os.environ.get("MARAUDER_SCAN_BUCKET", ""),
        users_map=_read_users_json(),
        giggso_rows=_rows(_BASELINE),
        allow_rows=_rows(_ALLOW), allow_code_rows=_rows(_ALLOW_CODE),
        deny_rows=_rows(_DENY_CUSTOM), deny_code_rows=_rows(_DENY_CODE),
    )
    st.session_state[_SEEDED] = True


def _db_context():
    """Org-scope PolicyContext from Postgres (auto-seeds first)."""
    from sqlalchemy import select
    from db.engine import get_session
    from db.models_identity import Org
    from db.policy_queries import load_policy_context
    slug = os.environ.get("COMPANY_SLUG", "dev")
    with get_session() as s:
        _ensure_seeded(s)
        org = (s.execute(select(Org).where(Org.slug == slug)).scalar_one_or_none()
               or s.execute(select(Org)).scalars().first())
        if org is None:
            return None
        return load_policy_context(s, org_id=org.id)


def load_org_policy_context():
    """Return an org-scope PolicyContext (cached). DB when DATABASE_URL is set,
    else CSV. None only if everything fails (score then runs policy-blind)."""
    if _CACHE in st.session_state:
        return st.session_state[_CACHE]
    ctx = None
    if os.environ.get("DATABASE_URL"):
        try:
            ctx = _db_context()
        except Exception as exc:
            log.warning("DB policy load failed, falling back to CSV: %s", exc)
            ctx = None
    if ctx is None:
        try:
            ctx = _csv_context()
        except Exception as exc:
            log.warning("CSV policy load failed - scoring policy-blind: %s", exc)
            ctx = None
    st.session_state[_CACHE] = ctx
    return ctx


def load_user_policy_context(email: str):
    """Effective PolicyContext for ONE user: org + their projects + their own
    list. Resolved fresh each call (no cache) so it reflects allow/deny edits
    immediately. Falls back to org scope on no DB / unknown user / error."""
    if not os.environ.get("DATABASE_URL"):
        return load_org_policy_context()
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
                return load_org_policy_context()
            return load_policy_context(s, org_id=org_id,
                                       user_id=(user.id if user else None),
                                       project_ids=project_ids)
    except Exception as exc:
        log.warning("user policy context failed, falling back to org: %s", exc)
        return load_org_policy_context()


def sync_scanned_users_from_events(events) -> None:
    """Upsert the scanned population (event owners) into the users table so
    Projects + user-scope pickers show everyone, not just the login allowlist.
    Once per session, lightweight (reuses already-loaded events). No-op
    without a DB."""
    if not os.environ.get("DATABASE_URL") or st.session_state.get("scanned_synced"):
        return
    emails = sorted({
        (e.get("owner") or e.get("email") or "").strip().lower()
        for e in (events or [])
    } - {""})
    if not emails:
        return
    try:
        from sqlalchemy import select
        from db.engine import get_session
        from db.models_identity import Org
        from db.seeding import upsert_users
        slug = os.environ.get("COMPANY_SLUG", "dev")
        with get_session() as s:
            org = (s.execute(select(Org).where(Org.slug == slug)).scalar_one_or_none()
                   or s.execute(select(Org)).scalars().first())
            if org is not None:
                upsert_users(s, org.id, {}, emails)
                s.commit()
        st.session_state["scanned_synced"] = True
    except Exception as exc:
        log.warning("scanned-user sync skipped: %s", exc)


def clear_policy_context() -> None:
    """Drop the cached context (call after an admin edits the lists)."""
    st.session_state.pop(_CACHE, None)
