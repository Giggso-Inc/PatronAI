# =============================================================
# FILE: routers/raven_enterprise_projects.py
# VERSION: 1.2.0
# UPDATED: 2026-08-16
# OWNER: Giggso Inc
# PURPOSE: Dedicated endpoints for RavenHub's automatic project sync — a
#          Project created in RavenHub (component-group) mirrors into
#          patron's own `projects` table, each Project Owner added in
#          RavenHub mirrors into patron's `project_members`, and a Project
#          permanently deleted in RavenHub deletes the patron mirror row
#          (and cascades its members/flags via ondelete="CASCADE" FKs).
#          Deliberately a NEW, separate router from
#          routers/ravenhub_projects.py (which backs the Streamlit
#          dashboard's project management and is left untouched) so this
#          always-on, service-to-service sync path has its own authz model
#          instead of reusing/complicating the existing one.
#
#          SCOPE: only RavenHub Project Owners sync to patron members — NOT
#          RavenHub's separate Developer Roster feature, and NOT any
#          automatic/inferred contributor. The only people who ever become
#          patron project members via this router are ones an admin
#          explicitly added as a RavenHub Project Owner (raven's own
#          require_admin gate on POST /owners already enforces "admin
#          added them manually").
#
#          NO ORG-ADMIN CHECK, ON PURPOSE: raven has already gated the
#          Project-creation / owner-add action on its side with its own
#          admin check (manage_component_groups) before this endpoint is
#          ever called. Requiring is_org_admin again here (or faking it
#          with a shim, as routers/ravenhub_projects.py does) would either
#          double-enforce a check raven already made, or fake a flag that
#          was never true. Trust here comes from the two shared secrets
#          below — api.py's bearer API_KEY (service-level) and the
#          X-Raven-Identity JWT (user-level, resolves the caller's org) —
#          not from an is_org_admin flag. Only call this from
#          raven-enterprise's server-to-server sync; never expose it to
#          end-user flows.
#
#          IDEMPOTENT: retrying project-sync with the same external_ref
#          (dropped response, network blip) returns the existing project
#          instead of creating a duplicate. A caller-supplied slug that
#          collides with an unrelated project's slug in the same org is
#          retried a few times with a numeric suffix. Member-sync is
#          idempotent too (a re-add of an existing member no-ops), and
#          get-or-creates the patron User by email — but refuses (409) if
#          that email already belongs to a DIFFERENT patron org, rather
#          than silently cross-linking someone else's identity.
#
#          PROJECT-DELETE IS IDEMPOTENT TOO: deleting an external_ref that's
#          already gone (double-fire, retry) 404s rather than erroring — the
#          raven-side caller treats that 404 as "nothing to clean up", not
#          a failure.
#
#          NOT SYNCED: member/owner REMOVAL. RavenHub has no remove-owner
#          feature at all yet (add-only) — when it gets one, add a matching
#          DELETE /projects/{id}/members/{user} endpoint here. Whole-project
#          delete (above) is the only removal sync that exists so far.
# AUDIT LOG:
#   v1.0.0  2026-07-24  Initial — project create/sync.
#   v1.1.0  2026-07-24  Add project-member sync (RavenHub Owners only).
#   v1.2.0  2026-08-16  Add project delete-sync — closes the orphan-row gap
#                       (confirmed live: 20 of 25 patron project rows had no
#                       matching raven group left after a raven-side delete).
# =============================================================

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from routers._raven_actor import resolve_actor as _resolve_actor
from routers._raven_identity import verify_ravenhub_identity

router = APIRouter(dependencies=[Depends(verify_ravenhub_identity)])


class SyncProjectRequest(BaseModel):
    slug: str
    display_name: str
    external_source: str
    external_ref: str


class ProjectOut(BaseModel):
    id: str
    slug: str
    display_name: str


class SyncMemberRequest(BaseModel):
    external_source: str
    external_ref: str
    email: str


class ProjectMemberOut(BaseModel):
    project_id: str
    user_id: str
    email: str


class ActionResponse(BaseModel):
    ok: bool
    message: str


def _require_db() -> None:
    import os
    if not os.environ.get("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="Projects require the policy database (DATABASE_URL not set).")


@router.post("/projects/sync", response_model=ProjectOut)
def sync_project_endpoint(body: SyncProjectRequest, email: str = Depends(verify_ravenhub_identity)) -> ProjectOut:
    _require_db()
    from sqlalchemy.exc import IntegrityError

    from db.engine import get_session
    from db.governance_crud import create_project_from_sync, get_project_by_external_ref

    with get_session() as s:
        _actor, org_id = _resolve_actor(s, email)

        existing = get_project_by_external_ref(
            s, org_id=org_id, external_source=body.external_source, external_ref=body.external_ref,
        )
        if existing is not None:
            return ProjectOut(id=str(existing.id), slug=existing.slug, display_name=existing.display_name)

        row = None
        try:
            for attempt in range(1, 6):
                candidate_slug = body.slug if attempt == 1 else f"{body.slug}-{attempt}"
                try:
                    row = create_project_from_sync(
                        s, org_id=org_id, slug=candidate_slug, display_name=body.display_name,
                        external_source=body.external_source, external_ref=body.external_ref,
                    )
                    break
                except IntegrityError:
                    s.rollback()
                    # The conflict may be the (org_id, slug) constraint (an
                    # unrelated project already has this slug - retry with a
                    # suffix) OR the external_ref constraint (a concurrent sync
                    # for this SAME upstream project just won the race). Check
                    # external_ref first - if it's there now, this is the
                    # idempotent-retry case the module docstring promises, not
                    # a slug collision, and must return the existing row rather
                    # than burn through slug-suffix attempts and 409.
                    existing = get_project_by_external_ref(
                        s, org_id=org_id, external_source=body.external_source, external_ref=body.external_ref,
                    )
                    if existing is not None:
                        return ProjectOut(id=str(existing.id), slug=existing.slug, display_name=existing.display_name)
                    continue
            if row is None:
                raise HTTPException(status_code=409, detail=f"Could not allocate a unique slug for '{body.slug}' after 5 attempts")
        except HTTPException:
            raise
        except Exception as exc:
            s.rollback()
            raise HTTPException(status_code=400, detail=str(exc))
    return ProjectOut(id=str(row.id), slug=row.slug, display_name=row.display_name)


@router.delete("/projects/{external_ref}", response_model=ActionResponse)
def delete_project_endpoint(external_ref: str, email: str = Depends(verify_ravenhub_identity)) -> ActionResponse:
    """Counterpart to sync_project_endpoint — deletes the patron mirror of a
    permanently-deleted RavenHub Project. external_ref is always
    external_source="ravenhub" here; this router only ever serves RavenHub.

    404 if no project with this external_ref exists — expected and normal
    for a Project that was still a draft (no owner ever added, so
    projects/sync never ran) at the time it was deleted in raven. The raven
    side treats that 404 as a no-op success, not an error.

    Child rows (project_members, raven_flagged_tools, etc.) cascade via
    ondelete="CASCADE" FKs — deleting the Project row is enough."""
    _require_db()
    from db.engine import get_session
    from db.governance_crud import delete_project_by_external_ref

    with get_session() as s:
        _actor, org_id = _resolve_actor(s, email)
        deleted = delete_project_by_external_ref(
            s, org_id=org_id, external_source="ravenhub", external_ref=external_ref,
        )
    if not deleted:
        raise HTTPException(status_code=404, detail=(
            f"No patron project found for external_ref='{external_ref}' — "
            "it was never synced (still a draft) or already deleted."
        ))
    return ActionResponse(ok=True, message="Project deleted.")


@router.post("/projects/members/sync", response_model=ProjectMemberOut)
def sync_member_endpoint(body: SyncMemberRequest, email: str = Depends(verify_ravenhub_identity)) -> ProjectMemberOut:
    _require_db()
    from db.engine import get_session
    from db.governance_crud import (
        add_project_member_from_sync, get_or_create_user_for_sync, get_project_by_external_ref,
    )

    with get_session() as s:
        _actor, org_id = _resolve_actor(s, email)

        project = get_project_by_external_ref(
            s, org_id=org_id, external_source=body.external_source, external_ref=body.external_ref,
        )
        if project is None:
            raise HTTPException(status_code=404, detail=(
                f"No patron project found for external_ref='{body.external_ref}' — "
                "the project create-sync may not have completed yet."
            ))
        try:
            member_user = get_or_create_user_for_sync(s, org_id=org_id, email=body.email)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except Exception as exc:
            s.rollback()
            raise HTTPException(status_code=400, detail=str(exc))

        try:
            add_project_member_from_sync(s, project_id=project.id, user_id=member_user.id)
        except Exception as exc:
            s.rollback()
            raise HTTPException(status_code=400, detail=str(exc))
    return ProjectMemberOut(project_id=str(project.id), user_id=str(member_user.id), email=member_user.email)
