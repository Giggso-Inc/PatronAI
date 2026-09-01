# =============================================================
# FILE: routers/ravenhub_governance_reads.py
# VERSION: 2.0.0
# UPDATED: 2026-07-31
# OWNER: Giggso Inc
# PURPOSE: Read-only export of dashboard/ui/tabs/provider_governance.py
#          as REST — the Overview cross-scope matrix, and the Manage
#          tab's read-only state (Inherited, Current lists, Newly
#          Found) for one org/project/user scope.
#          GET /governance/overview — every provider x its status at
#                                      every scope (Org/Project/User).
#                                      Mirrors provider_governance
#                                      .py:_overview().
#          GET /governance/scope    — one scope's governance state.
#                                      Mirrors _inherited_lists() +
#                                      _current_lists() + _newly_found()
#                                      (read portions only — see
#                                      ravenhub_governance_writes_lists.py
#                                      for the mutating actions).
#          Requires a policy-DB identity (db.policy_queries.get_identity)
#          resolved from the verified X-Raven-Identity email — same
#          identity check as routers/ravenhub.py (PR#9 review, C1),
#          shared via routers/_raven_identity.py, not duplicated.
#          Read-only. Does not modify or touch the Streamlit UI code
#          path — additive only.
# AUDIT LOG:
#   v1.0.0  2026-07-21  Initial — /governance/overview, /governance/scope.
#   v2.0.0  2026-07-31  ADR_2026-07-31: no more Giggso column/tier/override
#                       candidates — scope-first waterfall, fully-open
#                       flips. Dropped override_candidates/
#                       deny_override_candidates from GET /governance/scope
#                       (that action no longer exists to preview).
# =============================================================

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from routers._raven_actor import resolve_actor as _resolve_actor
from routers._raven_identity import verify_ravenhub_identity
from routers.ravenhub import _blob_store, _load_events

router = APIRouter(dependencies=[Depends(verify_ravenhub_identity)])


class GovernanceOverviewResponse(BaseModel):
    email: str
    providers: list


class GovernanceUserOut(BaseModel):
    id: str
    email: str
    display_name: Optional[str] = None


class GovernanceUsersResponse(BaseModel):
    users: list[GovernanceUserOut]


class GovernanceScopeResponse(BaseModel):
    email: str
    is_admin: bool
    scope: str
    project_id: Optional[str] = None
    user_id: Optional[str] = None
    inherited_observed: list
    inherited_policy: list
    current_allowed: list
    current_blocked: list
    newly_found: list


def _org_events(email: str) -> list:
    store = _blob_store(email)
    events, _summary, _y_summary, _source_date = _load_events(store, email, is_admin=True)
    return events


@router.get("/governance/overview", response_model=GovernanceOverviewResponse)
def get_governance_overview(email: str = Depends(verify_ravenhub_identity)) -> GovernanceOverviewResponse:
    """Every observed provider x its status at Org/Project/User scope.
    Project/User show WHO set each rule (name, not just state). Mirrors
    provider_governance.py:_overview() field-for-field (ADR_2026-07-31: no
    Giggso column)."""
    from sqlalchemy import select
    from db.engine import get_session
    from db.models_identity import Project, User
    from db.models_policy import ApprovedTool, BlacklistedTool
    from scoring.policy import _matches, _norm
    from scoring.provider_views import all_providers

    with get_session() as s:
        _actor, org_id = _resolve_actor(s, email)
        proj_name = {p.id: p.display_name for p in
                     s.execute(select(Project).where(Project.org_id == org_id)).scalars()}
        user_name = {u.id: (u.display_name or u.email) for u in
                     s.execute(select(User).where(User.org_id == org_id)).scalars()}
        ap = list(s.execute(select(ApprovedTool).where(ApprovedTool.org_id == org_id)).scalars())
        dn = list(s.execute(select(BlacklistedTool).where(BlacklistedTool.org_id == org_id)).scalars())

    def _org_state(prov):
        if any(r.scope == "org" and _matches(prov, {_norm(r.domain)}) for r in dn):
            return "deny"
        if any(r.scope == "org" and _matches(prov, {_norm(r.domain_pattern)}) for r in ap):
            return "allow"
        return None

    def _named(prov, scope, name_map, owner_attr):
        rows = [{"name": name_map.get(getattr(r, owner_attr), "?"), "state": "allow"} for r in ap
                if r.scope == scope and _matches(prov, {_norm(r.domain_pattern)})]
        rows += [{"name": name_map.get(getattr(r, owner_attr), "?"), "state": "deny"} for r in dn
                 if r.scope == scope and _matches(prov, {_norm(r.domain)})]
        return rows

    providers = all_providers(_org_events(email), None)
    rows = [{
        "provider": p["provider"], "category": p["category"] or "unknown",
        "org": _org_state(p["provider"]),
        "project": _named(p["provider"], "project", proj_name, "project_id"),
        "user": _named(p["provider"], "user", user_name, "user_id"),
    } for p in providers]
    return GovernanceOverviewResponse(email=email, providers=rows)


@router.get("/governance/users", response_model=GovernanceUsersResponse)
def get_governance_users(email: str = Depends(verify_ravenhub_identity)) -> GovernanceUsersResponse:
    """Policy-DB users in the actor's own org — for the FE's scope=user
    picker. NOT the same list as PatronAI's S3 admin roster
    (routers/ravenhub_users.py) or the cross-product Workforce merge
    (commonFE's identity.js) — scope=user governance rows are keyed by
    this table's UUID `id` (ProjectMember.user_id, ApprovedTool.user_id,
    BlacklistedTool.user_id all FK here), not by email, so the picker
    must send this id as user_id or GET /governance/scope's
    check_target_in_org will correctly 404/403 it as unrecognized."""
    from db.engine import get_session
    from db.governance_crud import list_org_users

    with get_session() as s:
        _actor, org_id = _resolve_actor(s, email)
        users = list_org_users(s, org_id)

    return GovernanceUsersResponse(users=[
        GovernanceUserOut(id=str(u.id), email=u.email, display_name=u.display_name)
        for u in users
    ])


@router.get("/governance/scope", response_model=GovernanceScopeResponse)
def get_governance_scope(
    scope: str = Query(..., pattern="^(org|project|user)$"),
    project_id: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None),
    email: str = Depends(verify_ravenhub_identity),
) -> GovernanceScopeResponse:
    """One scope's governance state: what's inherited (read-only, set
    above this scope), this scope's own allow/deny lists, the newly-found
    triage queue, and — admin only — what override/deny-override actions
    are available here. Mirrors provider_governance.py's Manage tab
    read-only sections (_inherited_lists, _current_lists, _newly_found)."""
    from db.engine import get_session
    from db.governance_crud import PolicyAuthzError, check_target_in_org, list_scope
    from db.models_policy import ApprovedTool, BlacklistedTool
    from db.policy_queries import load_policy_context, project_ids_for_user
    from scoring.provider_views import all_providers, newly_found as _newly_found_fn

    if scope == "project" and not project_id:
        raise HTTPException(status_code=422, detail="project_id required for scope=project")
    if scope == "user" and not user_id:
        raise HTTPException(status_code=422, detail="user_id required for scope=user")

    with get_session() as s:
        actor, org_id = _resolve_actor(s, email)
        is_admin = bool(actor.is_org_admin)
        # PR#9 review (C2): project_id/user_id are client-supplied query
        # params — verify they belong to this actor's org before using them
        # to load policy context, same check the write path now enforces
        # (governance_crud._check_scope_authz). Without this, any caller
        # could read another org's governance scope by guessing/reusing its
        # project_id/user_id.
        try:
            check_target_in_org(
                s, org_id=org_id,
                project_id=(project_id if scope == "project" else None),
                user_id=(user_id if scope == "user" else None),
            )
        except PolicyAuthzError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        tgt_projects = ([project_id] if scope == "project" else
                        (project_ids_for_user(s, user_id) if scope == "user" else []))
        eff = load_policy_context(s, org_id=org_id,
                                  user_id=(user_id if scope == "user" else None),
                                  project_ids=tgt_projects)
        events = _org_events(email)
        providers = all_providers(events, eff)

        # ADR_2026-07-31: scope-first — a wider-scope rule only "governs"
        # this scope when nothing at this scope (or narrower) exists for
        # the same provider. No Giggso tier to distinguish from org anymore.
        tiers = {"org": (),
                 "project": ("org_deny", "org_approve"),
                 "user": ("org_deny", "project_deny", "org_approve", "project_approve")}[scope]
        inherited_observed = [
            {"provider": p["provider"], "rule": p["tier"], "severity": p["max_severity"],
             "finding_count": p["finding_count"]}
            for p in providers if p["tier"] in tiers
        ]
        inherited_policy = []
        if scope in ("project", "user"):
            inherited_policy += [{"blocked_by": "org", "pattern": g} for g in sorted(eff.org_deny)]
        if scope == "user":
            inherited_policy += [{"blocked_by": "project", "pattern": g} for g in sorted(eff.project_deny)]

        current_allowed = [{"id": str(r.id), "pattern": r.domain_pattern,
                            "reason": r.reason,
                            "expires": str(r.valid_until) if r.valid_until else None}
                           for r in list_scope(s, ApprovedTool, org_id=org_id, scope=scope,
                                              project_id=project_id, user_id=user_id)]
        current_blocked = [{"id": str(r.id), "pattern": r.domain, "severity": r.severity,
                            "reason": r.reason}
                           for r in list_scope(s, BlacklistedTool, org_id=org_id, scope=scope,
                                              project_id=project_id, user_id=user_id)]

    return GovernanceScopeResponse(
        email=email, is_admin=is_admin, scope=scope, project_id=project_id, user_id=user_id,
        inherited_observed=inherited_observed, inherited_policy=inherited_policy,
        current_allowed=current_allowed, current_blocked=current_blocked,
        newly_found=_newly_found_fn(events, eff),
    )


class RavenFlagOut(BaseModel):
    id: str
    project_id: str
    project_name: str
    provider_pattern: str
    requested_by: str
    note: Optional[str] = None
    added_at: str


class ListRavenFlagsResponse(BaseModel):
    is_admin: bool
    flags: list[RavenFlagOut]


@router.get("/governance/raven-flags", response_model=ListRavenFlagsResponse)
def list_raven_flags(
    project_id: Optional[str] = Query(default=None), email: str = Depends(verify_ravenhub_identity)
) -> ListRavenFlagsResponse:
    """Pending MCP-governance flags forwarded from RavenHub — same list
    dashboard/ui/tabs/provider_governance.py's _raven_flagged_tools() renders
    in Streamlit (db.governance_crud.list_pending_raven_flags already
    existed; this is the first HTTP-reachable caller of it). Read-only —
    org-admins see every project; a non-admin only sees flags for projects
    they're actually a member of (project_ids_for_user), never every project
    in the org just by being an org member. Resolving requires org-admin,
    enforced separately in POST /governance/raven-flags/{flag_id}/resolve
    (ravenhub_governance_writes_lists.py).

    project_id is optional: omit it for the org-wide list (commonFE's
    Provider Governance page shows this before a specific project is picked
    in the Project-scope selector) — list_pending_raven_flags already
    supports project_id=None for exactly this, just never had an HTTP caller
    that omitted it before. When project_id IS supplied, check_target_in_org
    verifies it's a real project in the caller's own org first — same check
    the sibling GET /governance/scope (PR#9 review, C1/C2) already applies,
    a client-supplied id must never be trusted without it."""
    from db.engine import get_session
    from db.governance_crud import PolicyAuthzError, check_target_in_org, list_pending_raven_flags
    from db.models_identity import Project
    from db.policy_queries import project_ids_for_user

    with get_session() as s:
        actor, org_id = _resolve_actor(s, email)
        is_admin = bool(actor.is_org_admin)

        if project_id is not None:
            try:
                check_target_in_org(s, org_id=org_id, project_id=project_id)
            except PolicyAuthzError as exc:
                raise HTTPException(status_code=403, detail=str(exc))

        flags = list_pending_raven_flags(s, org_id=org_id, project_id=project_id)

        # Org-wide (project_id=None) case: a non-admin only sees flags for
        # projects they belong to — being any org member is not by itself
        # authorization to browse every other project's pending requests.
        # Admins keep the unrestricted org-wide view (that's the whole point
        # of this mode for them — resolving without clicking into each
        # project one at a time).
        if project_id is None and not is_admin:
            member_project_ids = set(project_ids_for_user(s, actor.id))
            flags = [f for f in flags if f.project_id in member_project_ids]

        project_names = {
            p.id: p.display_name
            for p in s.query(Project).filter(Project.org_id == org_id).all()
        }
        return ListRavenFlagsResponse(
            is_admin=is_admin,
            flags=[
                RavenFlagOut(
                    id=str(f.id), project_id=str(f.project_id),
                    project_name=project_names.get(f.project_id, "Unknown project"),
                    provider_pattern=f.provider_pattern, requested_by=f.requested_by,
                    note=f.note, added_at=f.added_at.isoformat() if f.added_at else "",
                )
                for f in flags
            ],
        )
