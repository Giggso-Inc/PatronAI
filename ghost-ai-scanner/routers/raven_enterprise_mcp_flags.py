# =============================================================
# FILE: routers/raven_enterprise_mcp_flags.py
# VERSION: 1.0.0
# UPDATED: 2026-07-26
# OWNER: Giggso Inc
# PURPOSE: Phase 2 of the raven<->patron MCP-governance-sync initiative (see
#          MCP_GOVERNANCE_SYNC_PLAN.md at the dashboard repo root). When a
#          RavenHub Project Owner approves an ungoverned-MCP notice, raven
#          calls this endpoint to raise a pending flag in patron's own
#          Provider Governance queue — a patron admin still makes the real
#          allow/deny decision (Phase 3); this only surfaces the request.
#
#          Same auth model as routers/raven_enterprise_projects.py: NO
#          org-admin check here on purpose — raven already gated the
#          approve action on its side (require_admin, manage_component_groups)
#          before this endpoint is ever called. Trust comes from the shared
#          API key + X-Raven-Identity JWT (verify_ravenhub_identity), same as
#          every other raven-enterprise endpoint.
#
#          IDEMPOTENT: a retried POST for the same still-pending (project,
#          provider) flag updates requested_by/note on the existing row
#          instead of creating a duplicate (db.governance_crud's
#          create_or_touch_raven_flag).
#
#          REQUIRES the Project to already be synced (external_ref lookup) —
#          404s otherwise, same contract as
#          raven_enterprise_projects.py's member-sync endpoint. Raven's
#          patron_sync.py is expected to treat a 404 here the same way it
#          already treats one on member-sync: NOT built as a self-heal
#          target (a Project not yet synced has no owners either, so no
#          notice could have been approved to reach this call in the first
#          place) — but the contract is documented here for whoever wires
#          the raven-side caller.
# =============================================================

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from routers._raven_actor import resolve_actor as _resolve_actor
from routers._raven_identity import verify_ravenhub_identity

router = APIRouter(dependencies=[Depends(verify_ravenhub_identity)])


class SyncMCPFlagRequest(BaseModel):
    external_source: str
    external_ref: str
    provider_pattern: str
    requested_by: str
    note: str | None = None


class MCPFlagOut(BaseModel):
    id: str
    project_id: str
    provider_pattern: str
    status: str


class ProviderProjectStatus(BaseModel):
    external_ref: str
    status: str


class ProviderStatusOut(BaseModel):
    provider_pattern: str
    org_approved: bool
    org_denied: bool
    projects: list[ProviderProjectStatus]


def _require_db() -> None:
    import os
    if not os.environ.get("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="Projects require the policy database (DATABASE_URL not set).")


@router.post("/mcp-flags/sync", response_model=MCPFlagOut)
def sync_mcp_flag_endpoint(body: SyncMCPFlagRequest, email: str = Depends(verify_ravenhub_identity)) -> MCPFlagOut:
    _require_db()
    from db.engine import get_session
    from db.governance_crud import create_or_touch_raven_flag, get_project_by_external_ref

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
            flag = create_or_touch_raven_flag(
                s, org_id=org_id, project_id=project.id,
                provider_pattern=body.provider_pattern,
                requested_by=body.requested_by, note=body.note,
            )
        except Exception as exc:
            s.rollback()
            raise HTTPException(status_code=400, detail=str(exc))
    return MCPFlagOut(id=str(flag.id), project_id=str(flag.project_id),
                      provider_pattern=flag.provider_pattern, status=flag.status)


@router.get("/mcp-flags/status", response_model=ProviderStatusOut)
def provider_status_endpoint(provider_pattern: str, email: str = Depends(verify_ravenhub_identity)) -> ProviderStatusOut:
    """Phase 4 cross-project awareness: has ANY project in this org already
    decided on this provider? raven calls this so a second project's owner
    reviewing the same MCP can see "Project Y already approved this in
    patron" before making their own call. Read-only, informational."""
    _require_db()
    from db.engine import get_session
    from db.governance_crud import get_provider_status_across_org

    with get_session() as s:
        _actor, org_id = _resolve_actor(s, email)
        status = get_provider_status_across_org(s, org_id=org_id, provider_pattern=provider_pattern)
    return ProviderStatusOut(**status)
