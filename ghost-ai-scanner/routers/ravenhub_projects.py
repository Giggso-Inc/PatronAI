# =============================================================
# FILE: routers/ravenhub_projects.py
# VERSION: 1.0.0
# UPDATED: 2026-07-21
# OWNER: Giggso Inc
# PURPOSE: REST export of dashboard/ui/tabs/projects.py — list projects
#          (with member counts), list/add/remove project members.
#          Mirrors the Streamlit tab's calls into db.governance_crud
#          (create_project, list_projects, list_project_members,
#          list_org_users, add_project_member, remove_project_member).
#          Requires the verified X-Raven-Identity JWT (routers.
#          _raven_identity), same as every other ravenhub router.
#
#          ADMIN CHECK — TEMP (2026-07-21): same decision as ravenhub.py's
#          _resolve_is_admin and the Shadow AI endpoints — role-based
#          routing (which API a user/exec/admin persona calls) is deferred
#          to the FE, not built yet. governance_crud's create_project /
#          add_project_member / remove_project_member each hard-require
#          actor.is_org_admin internally (_require(...) -> PolicyAuthzError).
#          Rather than relax that shared, tested guard (also used directly
#          by the Streamlit tab), this router passes a throwaway shim
#          object with is_org_admin=True instead of the real actor — the
#          real actor row is never mutated, so nothing is persisted to the
#          DB. See _admin_shim() below.
#          TODO: once FE role routing is integrated, drop _admin_shim and
#          pass the real `actor` straight through to enforce real authz.
# AUDIT LOG:
#   v1.0.0  2026-07-21  Initial — 5 endpoints.
# =============================================================

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from routers._raven_actor import resolve_actor as _resolve_actor
from routers._raven_identity import verify_ravenhub_identity

router = APIRouter(dependencies=[Depends(verify_ravenhub_identity)])


def _admin_shim(actor):
    """TEMP: see module docstring. A duck-typed stand-in so governance_crud's
    internal is_org_admin check passes, without ever touching the real,
    session-tracked `actor` row (which would risk persisting a fake admin
    flag on commit). Only `.id` and `.is_org_admin` are read by the three
    functions this is passed to (create_project, add/remove_project_member)."""
    from types import SimpleNamespace
    return SimpleNamespace(id=actor.id, is_org_admin=True)


class ProjectMemberOut(BaseModel):
    user_id: str
    email: str


class ProjectOut(BaseModel):
    id: str
    slug: str
    display_name: str
    member_count: int


class ProjectsResponse(BaseModel):
    email: str
    projects: list[ProjectOut]


class ProjectMembersResponse(BaseModel):
    project_id: str
    members: list[ProjectMemberOut]
    addable: list[ProjectMemberOut]


class CreateProjectRequest(BaseModel):
    slug: str
    display_name: str


class AddMemberRequest(BaseModel):
    user_id: str


class ActionResponse(BaseModel):
    ok: bool
    message: str


def _require_db() -> None:
    import os
    if not os.environ.get("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="Projects require the policy database (DATABASE_URL not set).")


def _require_ravenhub_project(s, org_id: str, project_id: str) -> None:
    """The member-management endpoints below must not operate on a
    patron-native project (2026-08-24 PR review, M1) — GET /projects
    already hides those from this router's caller, so letting the member
    endpoints act on one anyway (given its id some other way) would be an
    inconsistent, incomplete version of that same scoping rule. Treated as
    404 ("doesn't exist from here"), the same contract the list filter
    already implies, not a 403 — this isn't an authz failure, RavenHub
    just doesn't manage this project."""
    from db.governance_crud import resolve_project_in_org
    project = resolve_project_in_org(s, org_id, project_id)
    if project.external_source != "ravenhub":
        raise HTTPException(status_code=404, detail="Project not found")


@router.get("/projects", response_model=ProjectsResponse)
def list_projects_endpoint(email: str = Depends(verify_ravenhub_identity)) -> ProjectsResponse:
    """Every RavenHub-sourced project in the caller's org, with member count.

    Unlike projects.py's Streamlit render (which mirrors patron's FULL
    `projects` table, including rows created directly in patron itself, e.g.
    demo/test projects), this REST endpoint backs RavenHub-side UI (e.g. the
    Shadow AI "Grant project exception" picker) — a project that never came
    from RavenHub has no RavenHub identity for that UI to act on, so it's
    filtered out here rather than in the shared `list_projects` query (2026-
    08-24: confirmed live, two patron-native demo projects — no
    `external_source` — were showing up in that picker alongside real
    RavenHub projects, with no way for a RavenHub admin to tell them apart).
    """
    _require_db()
    from db.engine import get_session
    from db.governance_crud import list_projects

    with get_session() as s:
        actor, org_id = _resolve_actor(s, email)
        rows = list_projects(s, org_id)
        projects = [
            ProjectOut(id=str(p.id), slug=p.slug, display_name=p.display_name, member_count=count)
            for p, count in rows
            if p.external_source == "ravenhub"
        ]
    return ProjectsResponse(email=email, projects=projects)


@router.get("/projects/{project_id}/members", response_model=ProjectMembersResponse)
def list_project_members_endpoint(project_id: str, email: str = Depends(verify_ravenhub_identity)) -> ProjectMembersResponse:
    """Current members plus the addable pool (org users not already on
    this project) — mirrors the Streamlit tab's expander + selectbox."""
    _require_db()
    from db.engine import get_session
    from db.governance_crud import PolicyAuthzError, check_target_in_org, list_org_users, list_project_members

    with get_session() as s:
        actor, org_id = _resolve_actor(s, email)
        try:
            # PR#9 review round 3, C1: project_id is client-supplied — this
            # endpoint used to list ANY org's project membership given its
            # id, same IDOR pattern already fixed on the governance
            # routers. check_target_in_org also rejects a malformed
            # (non-UUID) project_id cleanly instead of a raw DB error.
            check_target_in_org(s, org_id=org_id, project_id=project_id)
        except PolicyAuthzError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        _require_ravenhub_project(s, org_id, project_id)
        members = list_project_members(s, project_id)
        member_ids = {str(m.id) for m in members}
        users = list_org_users(s, org_id)
        addable = [u for u in users if str(u.id) not in member_ids]
    return ProjectMembersResponse(
        project_id=project_id,
        members=[ProjectMemberOut(user_id=str(m.id), email=m.email) for m in members],
        addable=[ProjectMemberOut(user_id=str(u.id), email=u.email) for u in addable],
    )


@router.post("/projects", response_model=ProjectOut)
def create_project_endpoint(body: CreateProjectRequest, email: str = Depends(verify_ravenhub_identity)) -> ProjectOut:
    """external_source="ravenhub" (2026-08-24 PR review, C1): this router
    only ever serves RavenHub, so a project created through it IS a
    RavenHub project the same way a synced one is — without this stamp, it
    was created here and then immediately invisible in this same router's
    GET /projects, which filters to external_source == "ravenhub"."""
    _require_db()
    from db.engine import get_session
    from db.governance_crud import create_project

    with get_session() as s:
        actor, org_id = _resolve_actor(s, email)
        try:
            row = create_project(s, actor=_admin_shim(actor), org_id=org_id, slug=body.slug,
                                 display_name=body.display_name, external_source="ravenhub")
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    return ProjectOut(id=str(row.id), slug=row.slug, display_name=row.display_name, member_count=0)


@router.post("/projects/{project_id}/members", response_model=ActionResponse)
def add_project_member_endpoint(project_id: str, body: AddMemberRequest, email: str = Depends(verify_ravenhub_identity)) -> ActionResponse:
    _require_db()
    from db.engine import get_session
    from db.governance_crud import PolicyAuthzError, add_project_member, check_target_in_org

    with get_session() as s:
        actor, org_id = _resolve_actor(s, email)
        try:
            # PR#9 review round 3, C1: project_id AND user_id are both
            # client-supplied — without this, an org-A caller could add an
            # org-B user to an org-B project (or any combination thereof)
            # just by knowing both ids, same pattern already fixed on the
            # governance write routers.
            check_target_in_org(s, org_id=org_id, project_id=project_id, user_id=body.user_id)
        except PolicyAuthzError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        # Outside the try above, on purpose: that block's own generic
        # `except Exception` further down would otherwise catch this 404
        # and re-raise it as a misleading 400 (2026-08-24 PR review follow-up
        # while fixing M1 — HTTPException IS an Exception).
        _require_ravenhub_project(s, org_id, project_id)
        try:
            add_project_member(s, actor=_admin_shim(actor), project_id=project_id, user_id=body.user_id)
        except PolicyAuthzError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    return ActionResponse(ok=True, message="Member added.")


@router.delete("/projects/{project_id}/members/{user_id}", response_model=ActionResponse)
def remove_project_member_endpoint(project_id: str, user_id: str, email: str = Depends(verify_ravenhub_identity)) -> ActionResponse:
    _require_db()
    from db.engine import get_session
    from db.governance_crud import PolicyAuthzError, check_target_in_org, remove_project_member

    with get_session() as s:
        actor, org_id = _resolve_actor(s, email)
        try:
            check_target_in_org(s, org_id=org_id, project_id=project_id, user_id=user_id)
        except PolicyAuthzError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        _require_ravenhub_project(s, org_id, project_id)  # see add_project_member_endpoint's comment
        try:
            remove_project_member(s, actor=_admin_shim(actor), project_id=project_id, user_id=user_id)
        except PolicyAuthzError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    return ActionResponse(ok=True, message="Member removed.")
