# =============================================================
# FILE: dashboard/ui/policy_context_loader.py
# VERSION: 4.0.0
# UPDATED: 2026-07-31
# OWNER: Giggso Inc
# PURPOSE: Resolve a PolicyContext for the AI-Posture score.
#          - DB mode (DATABASE_URL set): read org-scope policy from
#            Postgres. The seed itself now runs at process startup
#            (main.py -> db.seed_bootstrap.seed_policy_db_from_s3(), on
#            every service restart) — this module only keeps a thin,
#            session-gated FALLBACK seed call for standalone Streamlit-only
#            dev runs that skip main.py entirely (RB_local-setup.md).
#          - CSV mode (no DB): read the S3 CSV lists directly.
#          Degrades gracefully to CSV / None on any failure (R3) — a policy
#          read must never crash the dashboard.
#          ADR_2026-07-31: no more Giggso-baseline S3 read here — the
#          starter deny content is seeded per-org from a LOCAL bundled file
#          by db.seeding.seed_all() (see src/db/seeding.py), not fetched
#          from S3 by this loader.
# DEPENDS: streamlit, scoring.*, db.* (when DATABASE_URL set), provider_lists_io
# AUDIT LOG:
#   v1.0.0  2026-06-29  CSV-backed org context (Phase A).
#   v2.0.0  2026-06-30  DB-backed org context + one-time S3->DB seed (F1/F3).
#   v3.0.0  2026-07-31  Drop the Giggso-baseline S3 read (ADR_2026-07-31).
#   v4.0.0  2026-07-31  Seed trigger moved to process startup (main.py) —
#                       this module's _ensure_seeded is now only a dev-mode
#                       fallback, delegating to db.seed_bootstrap so the
#                       S3-read logic lives in exactly one place.
# =============================================================

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

# S3 config keys -> expected columns. No `_BASELINE` entry — the Giggso
# baseline CSV is no longer read from S3 for scoring purposes
# (ADR_2026-07-31); see src/db/seeding.py::_starter_deny_rows for the local,
# per-org seed path.
_ALLOW       = ("config/authorized.csv", ["name", "domain_pattern", "notes"])
_ALLOW_CODE  = ("config/authorized_code.csv", ["name", "type", "pattern", "dept_scope", "notes"])
_DENY_CUSTOM = ("config/unauthorized_custom.csv", ["name", "category", "domain", "port", "severity", "notes"])
_DENY_CODE   = ("config/unauthorized_code_custom.csv", ["name", "type", "pattern", "severity", "notes"])


def _rows(key_cols):
    key, cols = key_cols
    # fillna("") — a blank CSV cell is pandas NaN (float); downstream code
    # calls .strip()/.lower() and would crash on a float. Coerce to "" here.
    return _io.read_csv_df(key, cols).fillna("").to_dict("records")


def _csv_context():
    """Org-scope PolicyContext straight from the S3 CSVs (no DB)."""
    return context_from_csv(
        authorized=_rows(_ALLOW), authorized_code=_rows(_ALLOW_CODE),
        unauthorized_custom=_rows(_DENY_CUSTOM),
        unauthorized_code_custom=_rows(_DENY_CODE),
    )


def _ensure_seeded() -> None:
    """Dev-mode FALLBACK seed only — the real trigger is main.py's startup
    call to db.seed_bootstrap.seed_policy_db_from_s3() on every service
    restart. This just covers a standalone `streamlit run` that never went
    through main.py. Idempotent (session_state gate + seed_all's own dedup),
    so calling it here even when main.py already seeded is harmless."""
    if st.session_state.get(_SEEDED):
        return
    from db.seed_bootstrap import seed_policy_db_from_s3
    seed_policy_db_from_s3()
    st.session_state[_SEEDED] = True


def _db_context():
    """Org-scope PolicyContext from Postgres (auto-seeds first)."""
    from sqlalchemy import select
    from db.engine import get_session
    from db.models_identity import Org
    from db.policy_queries import load_policy_context
    slug = os.environ.get("COMPANY_SLUG", "dev")
    _ensure_seeded()
    with get_session() as s:
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
