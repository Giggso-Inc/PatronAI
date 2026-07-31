# =============================================================
# FILE: src/db/policy_queries.py
# VERSION: 2.0.0
# UPDATED: 2026-07-31
# OWNER: Giggso Inc
# PURPOSE: DB-backed policy resolution. Builds the SAME scoring.policy.
#          PolicyContext the CSV resolver produces — so the scoring layer
#          is unchanged when the backend swaps.
#          db/ depends on scoring/ (one-way) — scoring/ never imports db/.
# DEPENDS: sqlalchemy, scoring.policy
# AUDIT LOG:
#   v1.0.0  2026-06-29  Initial (Phase C) + one-time Giggso baseline seed.
#   v2.0.0  2026-07-31  ADR_2026-07-31: removed seed_giggso_baseline() and
#                       the Giggso baseline read in load_policy_context() —
#                       the starter deny content is now seeded straight into
#                       each org's own org-scope BlacklistedTool rows by
#                       db.seeding.seed_org_lists(), not a separate table.
# =============================================================

import datetime as _dt

from sqlalchemy import select

from db.models_identity import ProjectMember, User
from db.models_policy import ApprovedTool, BlacklistedTool
from scoring.policy import PolicyContext, _norm


# ── DB → PolicyContext ────────────────────────────────────────────────

def _today():
    return _dt.date.today()


def _alive(valid_until) -> bool:
    return valid_until is None or valid_until >= _today()


def load_policy_context(session, *, org_id=None, user_id=None,
                        project_ids=()) -> PolicyContext:
    """Resolve a PolicyContext for one user from the policy DB.

    Approvals/denies are filtered by scope + (for time-boxed entries)
    expiry. No Giggso baseline, no override tiers (ADR_2026-07-31) — org's
    starter deny content lives as plain org-scope BlacklistedTool rows,
    seeded once per org by db.seeding.seed_org_lists()."""
    project_ids = set(project_ids or ())
    ctx = PolicyContext.empty()

    # Approvals — scoped + expiry-checked.
    for t in session.execute(
        select(ApprovedTool).where(ApprovedTool.org_id == org_id)
    ).scalars():
        if not _alive(t.valid_until):
            continue
        pat = _norm(t.domain_pattern)
        if not pat:
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
