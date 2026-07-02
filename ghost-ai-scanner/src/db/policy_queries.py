# =============================================================
# FILE: src/db/policy_queries.py
# VERSION: 1.0.0
# UPDATED: 2026-06-29
# OWNER: Giggso Inc
# PURPOSE: DB-backed policy resolution (Phase C, ADR_2026-06-29).
#          Builds the SAME scoring.policy.PolicyContext the CSV resolver
#          produces — so the scoring layer is unchanged when the backend
#          swaps. Also the ONE-TIME Giggso baseline seed (guarded by a
#          schema_migrations marker).
#          db/ depends on scoring/ (one-way) — scoring/ never imports db/.
# DEPENDS: sqlalchemy, scoring.policy
# =============================================================

import datetime as _dt

from sqlalchemy import select

from db.models_identity import ProjectMember, User
from db.models_policy import (
    ApprovedTool, BlacklistedTool, GiggsoBaselineDeny, SchemaMigration,
)
from scoring.policy import PolicyContext, _norm

GIGGSO_SEED_MARKER = "giggso_baseline_seed_v1"


# ── One-time Giggso baseline seed ─────────────────────────────────────

def seed_giggso_baseline(session, baseline_rows) -> int:
    """Insert the Giggso baseline (from config/unauthorized.csv rows) into
    giggso_baseline_deny. IDEMPOTENT BY DATA: dedups on `domain`, so it is
    safe to re-run every startup without duplicating rows (no fragile marker
    gate). Returns the count of NEW rows inserted."""
    existing = {d for (d,) in session.execute(select(GiggsoBaselineDeny.domain))}
    inserted = 0
    for row in baseline_rows or []:
        domain = _norm(row.get("domain"))
        if not domain or domain.startswith("#") or domain in existing:
            continue
        existing.add(domain)
        sev = (row.get("severity") or "").strip().upper() or None
        if sev not in (None, "LOW", "MEDIUM", "HIGH", "CRITICAL"):
            sev = None
        port = row.get("port")
        try:
            port = int(port) if str(port).strip() not in ("", "None") else None
        except (TypeError, ValueError):
            port = None
        session.add(GiggsoBaselineDeny(
            name=(row.get("name") or None),
            category=(row.get("category") or None),
            domain=domain, port=port, severity=sev,
            notes=(row.get("notes") or None),
        ))
        inserted += 1

    session.commit()
    return inserted


# ── DB → PolicyContext ────────────────────────────────────────────────

def _today():
    return _dt.date.today()


def _alive(valid_until) -> bool:
    return valid_until is None or valid_until >= _today()


def load_policy_context(session, *, org_id=None, user_id=None,
                        project_ids=()) -> PolicyContext:
    """Resolve a PolicyContext for one user from the policy DB.

    Approvals/denies are filtered by scope + (for time-boxed user acks)
    expiry. overrides_giggso rows feed the giggso_override set (capped
    ×0.5 tier), NOT org_approve — so a baseline tool is never silently
    cleared to ×0.1."""
    project_ids = set(project_ids or ())
    ctx = PolicyContext.empty()

    # Giggso baseline deny — global.
    for (dom,) in session.execute(select(GiggsoBaselineDeny.domain)):
        ctx.giggso_deny.add(_norm(dom))

    # Approvals (incl. overrides) — scoped + expiry-checked.
    for t in session.execute(
        select(ApprovedTool).where(ApprovedTool.org_id == org_id)
    ).scalars():
        if not _alive(t.valid_until):
            continue
        pat = _norm(t.domain_pattern)
        if not pat:
            continue
        if t.overrides_giggso:
            if t.scope == "org":
                ctx.giggso_override.add(pat)
            elif t.scope == "project" and t.project_id in project_ids:
                ctx.giggso_override_project.add(pat)
            elif t.scope == "user" and t.user_id == user_id:
                ctx.giggso_override_user.add(pat)
            continue
        if t.scope == "org":
            ctx.org_approve.add(pat)
        elif t.scope == "project" and t.project_id in project_ids:
            ctx.project_approve.add(pat)
        elif t.scope == "user" and t.user_id == user_id:
            ctx.user_ack.add(pat)

    # Denies — scoped.
    for b in session.execute(
        select(BlacklistedTool).where(BlacklistedTool.org_id == org_id)
    ).scalars():
        dom = _norm(b.domain)
        if not dom:
            continue
        if b.scope == "org":
            ctx.org_deny.add(dom)
        elif b.scope == "project" and b.project_id in project_ids:
            ctx.project_deny.add(dom)
        elif b.scope == "user" and b.user_id == user_id:
            ctx.user_deny.add(dom)

    return ctx


def project_ids_for_user(session, user_id) -> list:
    """Project ids a user belongs to (for project-scope resolution)."""
    return [
        tid for (tid,) in session.execute(
            select(ProjectMember.project_id).where(ProjectMember.user_id == user_id)
        )
    ]


def get_identity(session, email):
    """Resolve a login email to (User, org_id, project_ids). Returns
    (None, None, []) if the email is not a DB user yet."""
    user = session.execute(
        select(User).where(User.email == _norm(email))
    ).scalar_one_or_none()
    if user is None:
        return None, None, []
    return user, user.org_id, project_ids_for_user(session, user.id)
