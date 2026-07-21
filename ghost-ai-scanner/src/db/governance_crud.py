# =============================================================
# FILE: src/db/governance_crud.py
# VERSION: 1.3.0
# UPDATED: 2026-07-03
# OWNER: Giggso Inc
# PURPOSE: Write-path for the Provider Governance tab (Phase D) with
#          SERVER-SIDE authorisation (condition C8 — never trust a client
#          flag). Add/remove approved & blacklisted entries at org/project/
#          user scope; baseline overrides additionally pass the C1/C3/C4
#          guard (override_authz) AND the DB CHECK constraint.
# DEPENDS: sqlalchemy, db.models_policy, db.override_authz
# AUDIT LOG:
#   v1.0.0  2026-06-29  Initial add/remove/list + project mgmt.
#   v1.1.0  2026-07-01  add_* now idempotent per (scope,owner,pattern) — no
#                       duplicate list rows; plain approve UPGRADES to override
#                       in place. New move_to_allowed / move_to_blocked flip an
#                       entry between lists atomically; a baseline provider's
#                       flip-to-allow is forced through the guarded override
#                       path (reason+approver+expiry). commit= param added so
#                       the flips compose in a single transaction.
#   v1.2.0  2026-07-03  _check_scope_authz also refuses a cross-org write
#                       (org_id must equal actor.org_id) — defence-in-depth
#                       for any future API path (PR#8 review).
#   v1.3.0  2026-07-03  grant_deny_override: permit a wider-denied tool at a
#                       narrower scope (org-admin only, reason+approver+≤90d,
#                       project/user only). security_log 2026-07-03 D1-D7.
# =============================================================

import uuid as _uuid

from sqlalchemy import func, select

from db.models_identity import Project, ProjectMember, User
from db.models_policy import ApprovedTool, BlacklistedTool, GiggsoBaselineDeny
from db.override_authz import default_override_expiry, validate_override_request
from scoring.policy import _matches, _norm


class PolicyAuthzError(Exception):
    """Raised when a policy write violates server-side authorisation."""


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise PolicyAuthzError(msg)


def _get_by_id(session, model, row_id):
    """session.get() that treats a malformed (non-UUID) row_id the same as
    'not found' instead of letting the DB driver raise on the cast — a
    client-supplied id is untrusted input, never assume it's shaped right."""
    try:
        _uuid.UUID(str(row_id))
    except (ValueError, AttributeError, TypeError):
        return None
    return session.get(model, row_id)


def _check_scope_authz(actor, scope: str, user_id, org_id=None) -> None:
    """C8: org/project edits need org-admin; user edits only for oneself.

    Defence-in-depth (PR#8 review): a caller-supplied org_id must match the
    actor's own org — an org-A admin can never write into org B's lists even
    if an API path ever forwards a client-influenced org_id. Today every call
    site derives org_id server-side, so this only closes a future hole."""
    actor_org = getattr(actor, "org_id", None)
    if org_id is not None and actor_org is not None and org_id != actor_org:
        raise PolicyAuthzError("C8: cross-org policy write refused")
    if scope in ("org", "project"):
        _require(getattr(actor, "is_org_admin", False),
                 "C8: org/project policy edits require an org admin")
    elif scope == "user":
        # str() on both sides: user_id may arrive as a client-supplied str
        # (API request body) while actor.id is a SQLAlchemy uuid.UUID —
        # str==UUID is always False, which silently blocked every
        # self-service edit before this normalization.
        _require(getattr(actor, "is_org_admin", False) or str(user_id) == str(actor.id),
                 "C8: you may only edit your own personal list (org admins may edit any)")
    else:
        raise PolicyAuthzError(f"unknown scope {scope!r}")


def add_approved(session, *, actor, org_id, scope, name, provider_pattern,
                 project_id=None, user_id=None, reason=None, valid_until=None,
                 overrides_giggso=False, commit=True):
    """Add a whitelist entry. Baseline override requires the full C1/C3/C4
    guard to pass before the row is written.

    Idempotent per (scope, owner, pattern): a second call for a pattern that
    is already approved at that scope does NOT create a duplicate. If the
    existing row is a plain approve and the new call is a guarded override,
    the existing row is UPGRADED to the override in place (prevents the
    'same provider listed twice' state)."""
    _check_scope_authz(actor, scope, user_id, org_id=org_id)
    if overrides_giggso:
        errs = validate_override_request(
            is_org_admin=getattr(actor, "is_org_admin", False),
            scope=scope, reason=reason, approved_by=actor.id,
            valid_until=valid_until,
        )
        _require(not errs, "Override rejected — " + "; ".join(errs))

    pattern = (provider_pattern or "").strip().lower()
    existing = session.execute(
        select(ApprovedTool).where(
            ApprovedTool.org_id == org_id, ApprovedTool.scope == scope,
            ApprovedTool.project_id == project_id,
            ApprovedTool.user_id == user_id,
            ApprovedTool.domain_pattern == pattern,
        )
    ).scalars().first()
    if existing is not None:
        # Upgrade a plain approve to a guarded override; otherwise no-op.
        if overrides_giggso and not existing.overrides_giggso:
            existing.overrides_giggso = True
            existing.reason = reason
            existing.valid_until = valid_until
            existing.approved_by = actor.id
            if commit:
                session.commit()
        return existing

    row = ApprovedTool(
        org_id=org_id, scope=scope, name=name,
        domain_pattern=pattern,
        project_id=project_id, user_id=user_id, reason=reason,
        added_by=actor.id,
        approved_by=(actor.id if overrides_giggso else None),
        valid_until=valid_until, overrides_giggso=overrides_giggso,
    )
    session.add(row)
    if commit:
        session.commit()
    return row


def add_blacklisted(session, *, actor, org_id, scope, domain, name=None,
                    severity=None, category=None, project_id=None, user_id=None,
                    reason=None, commit=True):
    """Add a deny entry at the given scope (server-side authz enforced).
    Idempotent per (scope, owner, pattern) — no duplicate deny rows."""
    _check_scope_authz(actor, scope, user_id, org_id=org_id)
    pattern = (domain or "").strip().lower()
    existing = session.execute(
        select(BlacklistedTool).where(
            BlacklistedTool.org_id == org_id, BlacklistedTool.scope == scope,
            BlacklistedTool.project_id == project_id,
            BlacklistedTool.user_id == user_id,
            BlacklistedTool.domain == pattern,
        )
    ).scalars().first()
    if existing is not None:
        return existing
    row = BlacklistedTool(
        org_id=org_id, scope=scope, name=name,
        domain=pattern, severity=severity,
        category=category, project_id=project_id, user_id=user_id,
        reason=reason, added_by=actor.id,
    )
    session.add(row)
    if commit:
        session.commit()
    return row


def remove_entry(session, *, actor, model, row_id, commit=True) -> bool:
    """Delete an approved/blacklisted row after re-checking authz on it."""
    row = _get_by_id(session, model, row_id)
    if row is None:
        return False
    _check_scope_authz(actor, row.scope, getattr(row, "user_id", None), org_id=getattr(row, "org_id", None))
    session.delete(row)
    if commit:
        session.commit()
    return True


# ── Reclassify: flip an entry between the allow and deny lists ───────────

def is_giggso_blocked(session, pattern) -> bool:
    """True when a provider pattern is covered by the Giggso baseline.
    Allowing such a provider must go through the guarded override path."""
    globs = {_norm(d) for (d,) in session.execute(select(GiggsoBaselineDeny.domain))}
    return _matches(pattern, globs)


def move_to_allowed(session, *, actor, org_id, block_row_id,
                    reason=None, valid_until=None):
    """Flip a blacklisted row to the allow list at the SAME scope, atomically.
    If the provider is on the Giggso baseline the approve is written as a
    guarded OVERRIDE (reason + approver + ≤90-day expiry, band-floored); the
    guard rejects the move if those are missing. Returns True if it was a
    baseline override, False for a plain approve."""
    row = _get_by_id(session, BlacklistedTool, block_row_id)
    _require(row is not None, "blocked entry not found")
    _check_scope_authz(actor, row.scope, getattr(row, "user_id", None), org_id=getattr(row, "org_id", None))
    pattern = row.domain
    baseline = is_giggso_blocked(session, pattern)
    add_approved(
        session, actor=actor, org_id=org_id, scope=row.scope,
        project_id=row.project_id, user_id=row.user_id,
        name=(row.name or pattern), provider_pattern=pattern,
        overrides_giggso=baseline, reason=(reason if baseline else None),
        valid_until=((valid_until or default_override_expiry()) if baseline else None),
        commit=False,
    )
    session.delete(row)          # same transaction as the add above
    session.commit()
    return baseline


def move_to_blocked(session, *, actor, org_id, approve_row_id, severity="HIGH"):
    """Flip an approved row to the deny list at the SAME scope, atomically."""
    row = _get_by_id(session, ApprovedTool, approve_row_id)
    _require(row is not None, "approved entry not found")
    _check_scope_authz(actor, row.scope, getattr(row, "user_id", None), org_id=getattr(row, "org_id", None))
    add_blacklisted(
        session, actor=actor, org_id=org_id, scope=row.scope,
        project_id=row.project_id, user_id=row.user_id,
        domain=row.domain_pattern, name=row.name, severity=severity,
        commit=False,
    )
    session.delete(row)
    session.commit()
    return True


def grant_deny_override(session, *, actor, org_id, scope, provider_pattern,
                        project_id=None, user_id=None, reason=None,
                        valid_until=None, name=None, commit=True):
    """Permit, at a NARROWER scope, a tool a WIDER scope DENIED (security_log
    2026-07-03, D1-D7). Writes an ApprovedTool with overrides_deny=True.

    Guards: org-admin ONLY (D1 — never the project member / user themselves);
    reason + approver + ≤90-day expiry (D3, via validate_override_request);
    scope must be project/user (an org can't deny-override its own org deny).
    The Giggso floor is untouchable (D4) — a giggso-blocked tool is resolved
    before org/project deny in the waterfall, so this never reaches it; callers
    must not offer giggso-denied tools here. Idempotent per (scope,owner,pattern)."""
    if scope not in ("project", "user"):
        raise PolicyAuthzError("D1: deny-override is only valid at project/user scope")
    _require(getattr(actor, "is_org_admin", False),
             "D1: only an org admin may grant a deny-override")
    _check_scope_authz(actor, scope, user_id, org_id=org_id)
    errs = validate_override_request(
        is_org_admin=getattr(actor, "is_org_admin", False),
        scope=scope, reason=reason, approved_by=actor.id, valid_until=valid_until,
    )
    _require(not errs, "Deny-override rejected — " + "; ".join(errs))

    pat = (provider_pattern or "").strip().lower()
    existing = session.execute(
        select(ApprovedTool).where(
            ApprovedTool.org_id == org_id, ApprovedTool.scope == scope,
            ApprovedTool.project_id == project_id,
            ApprovedTool.user_id == user_id,
            ApprovedTool.domain_pattern == pat,
        )
    ).scalars().first()
    if existing is not None:
        existing.overrides_deny = True
        existing.reason = reason
        existing.valid_until = valid_until
        existing.approved_by = actor.id
        if commit:
            session.commit()
        return existing
    row = ApprovedTool(
        org_id=org_id, scope=scope, name=(name or pat), domain_pattern=pat,
        project_id=project_id, user_id=user_id, reason=reason,
        added_by=actor.id, approved_by=actor.id, valid_until=valid_until,
        overrides_deny=True,
    )
    session.add(row)
    if commit:
        session.commit()
    return row


def list_scope(session, model, *, org_id, scope, project_id=None, user_id=None):
    """List approved/blacklisted rows at one scope."""
    q = select(model).where(model.org_id == org_id, model.scope == scope)
    if scope == "project":
        q = q.where(model.project_id == project_id)
    elif scope == "user":
        q = q.where(model.user_id == user_id)
    return list(session.execute(q).scalars())


# ── Project management (org-admin only) ─────────────────────────────────

def create_project(session, *, actor, org_id, slug, display_name) -> Project:
    _require(getattr(actor, "is_org_admin", False), "C8: only an org admin may create projects")
    t = Project(org_id=org_id, slug=_norm(slug), display_name=display_name)
    session.add(t)
    session.commit()
    return t


def add_project_member(session, *, actor, project_id, user_id, is_project_admin=False) -> None:
    _require(getattr(actor, "is_org_admin", False), "C8: only an org admin may add members")
    if session.get(ProjectMember, (project_id, user_id)) is None:
        session.add(ProjectMember(project_id=project_id, user_id=user_id, is_project_admin=is_project_admin))
        session.commit()


def remove_project_member(session, *, actor, project_id, user_id) -> None:
    _require(getattr(actor, "is_org_admin", False), "C8: only an org admin may remove members")
    tm = session.get(ProjectMember, (project_id, user_id))
    if tm is not None:
        session.delete(tm)
        session.commit()


def list_projects(session, org_id):
    """Return [(Project, member_count)] for an org."""
    rows = session.execute(
        select(Project, func.count(ProjectMember.user_id))
        .outerjoin(ProjectMember, ProjectMember.project_id == Project.id)
        .where(Project.org_id == org_id)
        .group_by(Project.id)
    ).all()
    return [(t, n) for (t, n) in rows]


def list_org_users(session, org_id):
    """All users in an org (for member pickers)."""
    return list(session.execute(
        select(User).where(User.org_id == org_id).order_by(User.email)
    ).scalars())


def list_project_members(session, project_id):
    """Users belonging to a project."""
    return list(session.execute(
        select(User).join(ProjectMember, ProjectMember.user_id == User.id)
        .where(ProjectMember.project_id == project_id).order_by(User.email)
    ).scalars())
