# =============================================================
# FILE: src/db/governance_crud.py
# VERSION: 2.0.0
# UPDATED: 2026-07-31
# OWNER: Giggso Inc
# PURPOSE: Write-path for the Provider Governance tab with SERVER-SIDE
#          authorisation (condition C8 — never trust a client flag).
#          Add/remove approved & blacklisted entries at org/project/user
#          scope. Per ADR_2026-07-31: no more Giggso baseline, no more
#          guarded overrides — flipping any entry is fully open (org-admin
#          for org/project scope, self-service for user scope, same as
#          every other write here). The one hard rule left is OQ-4: a
#          pattern can never hold both an approve and a deny row at the
#          SAME scope — enforced here at write time.
# DEPENDS: sqlalchemy, db.models_policy
# AUDIT LOG:
#   v1.0.0  2026-06-29  Initial add/remove/list + project mgmt.
#   v1.1.0  2026-07-01  add_* now idempotent per (scope,owner,pattern) — no
#                       duplicate list rows. New move_to_allowed / move_to_blocked
#                       flip an entry between lists atomically. commit= param
#                       added so the flips compose in a single transaction.
#   v1.2.0  2026-07-03  _check_scope_authz also refuses a cross-org write
#                       (org_id must equal actor.org_id) — defence-in-depth
#                       for any future API path (PR#8 review).
#   v1.3.0  2026-07-03  (superseded) grant_deny_override — removed in v2.0.0.
#   v2.0.0  2026-07-31  ADR_2026-07-31: removed the Giggso baseline tier and
#                       all guarded-override machinery (is_giggso_blocked,
#                       grant_deny_override, the baseline branch in
#                       move_to_allowed, overrides_giggso/overrides_deny).
#                       Added _check_no_opposite_polarity (OQ-4) to
#                       add_approved/add_blacklisted.
# =============================================================

import uuid as _uuid
from datetime import datetime, timezone

from sqlalchemy import func, select

from db.models_identity import Project, ProjectMember, User
from db.models_policy import ApprovedTool, BlacklistedTool, RavenFlaggedTool
from scoring.policy import _norm


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


def check_target_in_org(session, *, org_id, project_id=None, user_id=None) -> None:
    """PR#9 review (C1/C2): a client-supplied project_id/user_id must
    actually belong to org_id, not just be well-formed. Before this, an
    org-A admin (or any caller who could satisfy the scope check) could
    hand in an org-B project_id/user_id and read or write org-B's
    project/user policy lists — org_id equality alone never verified the
    id it was paired with was real for that org. Shared by the write
    path (_check_scope_authz below) and the read-only GET /governance/
    scope endpoint (ravenhub_governance_reads.py), which had no
    ownership check at all."""
    if project_id is not None:
        proj = _get_by_id(session, Project, project_id)
        _require(proj is not None and proj.org_id == org_id, "project_id not found in this org")
    if user_id is not None:
        usr = _get_by_id(session, User, user_id)
        _require(usr is not None and usr.org_id == org_id, "user_id not found in this org")


def _check_scope_authz(actor, scope: str, user_id, org_id=None, *,
                       project_id=None, session=None) -> None:
    """C8: org/project edits need org-admin; user edits only for oneself.

    Defence-in-depth (PR#8 review): a caller-supplied org_id must match the
    actor's own org — an org-A admin can never write into org B's lists even
    if an API path ever forwards a client-influenced org_id. Today every call
    site derives org_id server-side, so this only closes a future hole.

    `project_id`/`session` (PR#9 review, C1): when a session is supplied
    (every real call site passes one), a write additionally verifies
    ANY target project_id/user_id it was given belongs to org_id via
    check_target_in_org — not just whichever one matches `scope`.
    add_approved/add_blacklisted both accept both
    fields from the request body and persist both onto the row
    regardless of scope, so a scope="user" write carrying an unrelated
    (cross-org or bogus) project_id must be rejected too, even though
    scope="user" writes don't need a project_id at all — otherwise an
    unvalidated id sits on the row, inert only until some future read
    joins on the "wrong" field (PR#9 review round 2, H1). Kept optional
    (default None) so this stays a pure-authz check for any future
    caller that hasn't wired a session through, same as the org_id
    check being conditional above."""
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
    if session is not None:
        check_target_in_org(session, org_id=org_id, project_id=project_id, user_id=user_id)


def _check_no_opposite_polarity(session, *, org_id, scope, project_id, user_id,
                                pattern, incoming: str) -> None:
    """OQ-4 (ADR_2026-07-31): the same (org_id, scope, project_id, user_id,
    pattern) may never hold both an approve and a deny row. `incoming` is
    the polarity about to be written ("approve" or "deny") — reject if the
    OPPOSITE polarity already has a live row for the identical key. Callers
    that want to flip must remove the opposite row first (see
    move_to_allowed/move_to_blocked, which do exactly that atomically)."""
    other_model = BlacklistedTool if incoming == "approve" else ApprovedTool
    other_pattern_col = other_model.domain if incoming == "approve" else other_model.domain_pattern
    conflict = session.execute(
        select(other_model).where(
            other_model.org_id == org_id, other_model.scope == scope,
            other_model.project_id == project_id, other_model.user_id == user_id,
            other_pattern_col == pattern,
        )
    ).scalars().first()
    _require(conflict is None,
             f"OQ-4: '{pattern}' is already "
             f"{'blocked' if incoming == 'approve' else 'approved'} at {scope} scope — "
             "remove that entry before adding the opposite one")


def add_approved(session, *, actor, org_id, scope, name, provider_pattern,
                 project_id=None, user_id=None, reason=None, valid_until=None,
                 commit=True):
    """Add a whitelist entry (server-side authz enforced; fully open per
    ADR_2026-07-31 — no reason/approver/expiry requirement).

    Idempotent per (scope, owner, pattern): a second call for a pattern that
    is already approved at that scope does NOT create a duplicate."""
    _check_scope_authz(actor, scope, user_id, org_id=org_id, project_id=project_id, session=session)
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
        return existing
    _check_no_opposite_polarity(session, org_id=org_id, scope=scope,
                                project_id=project_id, user_id=user_id,
                                pattern=pattern, incoming="approve")

    row = ApprovedTool(
        org_id=org_id, scope=scope, name=name,
        domain_pattern=pattern,
        project_id=project_id, user_id=user_id, reason=reason,
        added_by=actor.id, approved_by=actor.id, valid_until=valid_until,
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
    _check_scope_authz(actor, scope, user_id, org_id=org_id, project_id=project_id, session=session)
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
    _check_no_opposite_polarity(session, org_id=org_id, scope=scope,
                                project_id=project_id, user_id=user_id,
                                pattern=pattern, incoming="deny")

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
    _check_scope_authz(actor, row.scope, getattr(row, "user_id", None), org_id=getattr(row, "org_id", None),
                       project_id=getattr(row, "project_id", None), session=session)
    session.delete(row)
    if commit:
        session.commit()
    return True


# ── Reclassify: flip an entry between the allow and deny lists ───────────
# Fully open per ADR_2026-07-31 — no reason/approver/expiry, no Giggso
# baseline to guard against. Both flips delete the source row FIRST (and
# flush) so add_approved/add_blacklisted's OQ-4 conflict check never sees
# the row being replaced as a false-positive conflict with itself.

def move_to_allowed(session, *, actor, org_id, block_row_id, reason=None):
    """Flip a blacklisted row to the allow list at the SAME scope, atomically."""
    row = _get_by_id(session, BlacklistedTool, block_row_id)
    _require(row is not None, "blocked entry not found")
    _check_scope_authz(actor, row.scope, getattr(row, "user_id", None), org_id=getattr(row, "org_id", None),
                       project_id=getattr(row, "project_id", None), session=session)
    scope, project_id, user_id, pattern, name = (
        row.scope, row.project_id, row.user_id, row.domain, row.name,
    )
    session.delete(row)
    session.flush()
    add_approved(
        session, actor=actor, org_id=org_id, scope=scope,
        project_id=project_id, user_id=user_id,
        name=(name or pattern), provider_pattern=pattern, reason=reason,
        commit=False,
    )
    session.commit()


def move_to_blocked(session, *, actor, org_id, approve_row_id, severity="HIGH"):
    """Flip an approved row to the deny list at the SAME scope, atomically."""
    row = _get_by_id(session, ApprovedTool, approve_row_id)
    _require(row is not None, "approved entry not found")
    _check_scope_authz(actor, row.scope, getattr(row, "user_id", None), org_id=getattr(row, "org_id", None),
                       project_id=getattr(row, "project_id", None), session=session)
    scope, project_id, user_id, pattern, name = (
        row.scope, row.project_id, row.user_id, row.domain_pattern, row.name,
    )
    session.delete(row)
    session.flush()
    add_blacklisted(
        session, actor=actor, org_id=org_id, scope=scope,
        project_id=project_id, user_id=user_id,
        domain=pattern, name=name, severity=severity,
        commit=False,
    )
    session.commit()


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


def create_project_from_sync(session, *, org_id, slug, display_name, external_source, external_ref) -> Project:
    """Used only by routers/raven_enterprise_projects.py's automatic
    RavenHub -> patron sync — deliberately takes no `actor` and does not
    call _require(is_org_admin): this is a trusted server-to-server call,
    authenticated at the router layer by the shared API key + X-Raven-Identity
    JWT, not a user-initiated action needing per-user authz. Never call this
    from a user-facing flow (Streamlit tab or ravenhub_projects.py) — those
    use create_project() above, unchanged."""
    t = Project(
        org_id=org_id, slug=_norm(slug), display_name=display_name,
        external_source=external_source, external_ref=external_ref,
    )
    session.add(t)
    session.commit()
    return t


def get_project_by_external_ref(session, *, org_id, external_source, external_ref) -> Project | None:
    """Idempotent lookup for a retried upstream-system sync — look up by
    (org_id, external_source, external_ref) before ever attempting a create,
    so a dropped response or a second sync attempt never creates a duplicate
    project."""
    return session.execute(
        select(Project).where(
            Project.org_id == org_id,
            Project.external_source == external_source,
            Project.external_ref == external_ref,
        )
    ).scalar_one_or_none()


def delete_project_by_external_ref(session, *, org_id, external_source, external_ref) -> bool:
    """Used only by routers/raven_enterprise_projects.py's automatic
    RavenHub -> patron delete-sync — same trust model as
    create_project_from_sync (no `actor`, no is_org_admin check: a trusted
    server-to-server call already authenticated at the router layer).

    Returns False if no matching project exists (never synced, or already
    deleted) — the router turns that into a 404, which the raven-side caller
    treats as a no-op, not a failure. Child rows (project_members,
    raven_flagged_tools, etc.) all have ondelete="CASCADE" FKs onto
    projects.id, so deleting the row is enough — no manual child cleanup
    needed here, unlike raven's own component_group_lifecycle.py which has
    no DB-level cascade and must delete each child table by hand."""
    project = get_project_by_external_ref(
        session, org_id=org_id, external_source=external_source, external_ref=external_ref,
    )
    if project is None:
        return False
    session.delete(project)
    session.commit()
    return True


def add_project_member(session, *, actor, project_id, user_id, is_project_admin=False) -> None:
    _require(getattr(actor, "is_org_admin", False), "C8: only an org admin may add members")
    if session.get(ProjectMember, (project_id, user_id)) is None:
        session.add(ProjectMember(project_id=project_id, user_id=user_id, is_project_admin=is_project_admin))
        session.commit()


def get_or_create_user_for_sync(session, *, org_id, email) -> User:
    """Get-or-create a User by email for the RavenHub owner-sync (see
    routers/raven_enterprise_projects.py). Mirrors seeding.upsert_users's
    existing member-provisioning convention (no password, is_org_admin=False)
    — this only creates an identity/scope record for FK purposes, the same
    as a scanned-only "member" today; it grants no new login capability.

    Raises ValueError if the email already belongs to a DIFFERENT patron org
    — User.email is globally unique, so this refuses to silently cross-link
    someone else's identity into this org rather than misassign them."""
    from db.seeding import _display_name
    norm_email = _norm(email)
    user = session.execute(select(User).where(User.email == norm_email)).scalar_one_or_none()
    if user is not None:
        if user.org_id != org_id:
            raise ValueError(f"'{norm_email}' already belongs to a different patron org")
        return user
    user = User(org_id=org_id, email=norm_email, display_name=_display_name(norm_email), is_org_admin=False)
    session.add(user)
    session.flush()
    return user


def add_project_member_from_sync(session, *, project_id, user_id) -> None:
    """Used only by routers/raven_enterprise_projects.py's automatic
    RavenHub -> patron owner sync — no actor/is_org_admin check, same
    rationale as create_project_from_sync. Idempotent: no-ops if the user is
    already a member (mirrors add_project_member's own idempotency)."""
    if session.get(ProjectMember, (project_id, user_id)) is None:
        session.add(ProjectMember(project_id=project_id, user_id=user_id))
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


# ── RavenHub MCP-governance flag sync (Phase 2) ─────────────────────────────
# Used only by routers/raven_enterprise_mcp_flags.py's automatic RavenHub ->
# patron sync — same no-actor, no is_org_admin rationale as
# create_project_from_sync above: this is a trusted server-to-server call,
# authenticated at the router layer, not a user-initiated action.

def _raven_mcp_match_pattern(provider_pattern: str) -> str:
    """Raven's `mcp_name` (e.g. "gmail") is the arbitrary local key from a
    developer's `.mcp.json`/`mcpServers` config — NOT the same string patron's
    own scanner produces for the same MCP server. Patron's endpoint scan
    (agent_explode.py's _provider_for, for ftype == "mcp_server") reports it
    as `mcp:<mcp_host>:<server_name>` — a compound, host-prefixed identifier.
    `_matches()` (scoring/policy.py) is exact-or-fnmatch-glob, so an
    ApprovedTool/BlacklistedTool row storing the bare raven name would never
    match what patron's own scanner independently reports for that MCP server
    on any host — the approval/deny decision would be inert. Wrapping it as
    `mcp:*:<name>` puts it in the SAME namespace patron's scanner uses, so an
    approval actually governs future patron-scanned occurrences of that
    server, on whatever host they're found."""
    return f"mcp:*:{(provider_pattern or '').strip().lower()}"

def create_or_touch_raven_flag(session, *, org_id, project_id, provider_pattern,
                               requested_by, note=None) -> RavenFlaggedTool:
    """Idempotent per (project_id, provider_pattern) while status='pending'
    (enforced by uq_raven_flagged_tools_pending) — a raven retry (dropped
    response, network blip) updates requested_by/note on the existing
    pending row instead of creating a duplicate. Once a flag has been
    resolved (Phase 3), the SAME (project, provider) recurring is a genuinely
    NEW pending row — a past decision must not silently swallow a fresh
    request forever."""
    pattern = (provider_pattern or "").strip().lower()
    existing = session.execute(
        select(RavenFlaggedTool).where(
            RavenFlaggedTool.project_id == project_id,
            RavenFlaggedTool.provider_pattern == pattern,
            RavenFlaggedTool.status == "pending",
        )
    ).scalars().first()
    if existing is not None:
        existing.requested_by = requested_by
        if note is not None:
            existing.note = note
        session.commit()
        return existing

    row = RavenFlaggedTool(
        org_id=org_id, project_id=project_id, provider_pattern=pattern,
        requested_by=requested_by, note=note,
    )
    session.add(row)
    session.commit()
    return row


def list_pending_raven_flags(session, *, org_id, project_id=None) -> list[RavenFlaggedTool]:
    """Pending flags for the Provider Governance tab (Phase 3) to render.
    Scoped by org always; project_id further narrows to one Project."""
    conditions = [RavenFlaggedTool.org_id == org_id, RavenFlaggedTool.status == "pending"]
    if project_id is not None:
        conditions.append(RavenFlaggedTool.project_id == project_id)
    return list(session.execute(
        select(RavenFlaggedTool).where(*conditions).order_by(RavenFlaggedTool.added_at.desc())
    ).scalars())


def get_provider_status_across_org(session, *, org_id, provider_pattern) -> dict:
    """Phase 4 cross-project awareness: for a given provider, what has this
    org already decided, anywhere? Lets raven show "Project Y already
    approved this" when a second project's owner is reviewing the same MCP,
    without raven needing to know patron's internal project ids — Project
    rows carry `external_ref` (raven's own group_id) when synced, so the
    mapping back to a raven Project is direct.

    Read-only, no actor/authz required — this is informational context, not
    a write; matches the read_posture-only gating raven uses for the
    equivalent GET /mcp-notices.

    Queries using the SAME `mcp:*:<name>` wrapped shape resolve_raven_flag
    writes (see _raven_mcp_match_pattern) — a raven-originated approval is
    the only source of these rows in this org, so the lookup key must match
    what was actually written, not the bare raven name."""
    match_pattern = _raven_mcp_match_pattern(provider_pattern)
    org_approved = session.execute(
        select(ApprovedTool).where(
            ApprovedTool.org_id == org_id, ApprovedTool.scope == "org",
            ApprovedTool.domain_pattern == match_pattern,
        )
    ).scalars().first() is not None
    org_denied = session.execute(
        select(BlacklistedTool).where(
            BlacklistedTool.org_id == org_id, BlacklistedTool.scope == "org",
            BlacklistedTool.domain == match_pattern,
        )
    ).scalars().first() is not None

    project_rows = []
    approved_projects = session.execute(
        select(Project.external_ref).where(
            Project.org_id == org_id, Project.external_ref.is_not(None),
            Project.id.in_(select(ApprovedTool.project_id).where(
                ApprovedTool.org_id == org_id, ApprovedTool.scope == "project",
                ApprovedTool.domain_pattern == match_pattern,
            )),
        )
    ).scalars().all()
    project_rows += [{"external_ref": ref, "status": "approved"} for ref in approved_projects]
    denied_projects = session.execute(
        select(Project.external_ref).where(
            Project.org_id == org_id, Project.external_ref.is_not(None),
            Project.id.in_(select(BlacklistedTool.project_id).where(
                BlacklistedTool.org_id == org_id, BlacklistedTool.scope == "project",
                BlacklistedTool.domain == match_pattern,
            )),
        )
    ).scalars().all()
    project_rows += [{"external_ref": ref, "status": "denied"} for ref in denied_projects]

    return {
        "provider_pattern": (provider_pattern or "").strip().lower(),
        "org_approved": org_approved,
        "org_denied": org_denied,
        "projects": project_rows,
    }


def resolve_raven_flag(session, *, actor, org_id, project_id, flag_id, approve: bool,
                       reason=None) -> RavenFlaggedTool | None:
    """Provider Governance's Approve/Deny action on a RavenHub-forwarded flag
    (Phase 3). Writes the REAL decision into approved_tools/blacklisted_tools
    at project scope (server-side authz enforced by add_approved/
    add_blacklisted, same as every other governance write in this file — a
    RavenHub-originated request is NOT a bypass of C8), then marks the flag
    resolved, atomically (same commit=False + single session.commit()
    composition as move_to_allowed/move_to_blocked above).

    Returns None if no matching PENDING flag exists (already resolved, or
    wrong org/project) — the caller (Streamlit) should treat this as a
    no-op/"already handled", never a crash."""
    flag = session.execute(
        select(RavenFlaggedTool).where(
            RavenFlaggedTool.id == flag_id, RavenFlaggedTool.org_id == org_id,
            RavenFlaggedTool.project_id == project_id, RavenFlaggedTool.status == "pending",
        )
    ).scalars().first()
    if flag is None:
        return None

    match_pattern = _raven_mcp_match_pattern(flag.provider_pattern)
    if approve:
        add_approved(
            session, actor=actor, org_id=org_id, scope="project", project_id=project_id,
            name=flag.provider_pattern, provider_pattern=match_pattern,
            reason=reason or f"Requested via RavenHub by {flag.requested_by}",
            commit=False,
        )
    else:
        add_blacklisted(
            session, actor=actor, org_id=org_id, scope="project", project_id=project_id,
            domain=match_pattern, name=flag.provider_pattern, severity="HIGH",
            reason=reason or f"Requested via RavenHub by {flag.requested_by}",
            commit=False,
        )
    flag.status = "approved" if approve else "denied"
    flag.resolved_by = getattr(actor, "id", None)
    flag.resolved_at = datetime.now(timezone.utc)
    session.commit()
    return flag
