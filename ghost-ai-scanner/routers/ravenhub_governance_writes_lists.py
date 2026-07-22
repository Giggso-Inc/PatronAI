# =============================================================
# FILE: routers/ravenhub_governance_writes_lists.py
# VERSION: 1.0.0
# UPDATED: 2026-07-21
# OWNER: Giggso Inc
# PURPOSE: Write actions for Provider Governance's Newly Found triage
#          and This-scope lists — approve, block, flip (allow<->block),
#          remove. Mirrors provider_governance.py's _newly_found() and
#          _list_block() action buttons.
#          POST /governance/approve          — add_approved (plain;
#                                               NOT the guarded Giggso
#                                               override — see
#                                               ravenhub_governance_
#                                               writes_overrides.py for
#                                               that, on purpose, so a
#                                               stray flag here can't
#                                               grant one).
#          POST /governance/block            — add_blacklisted.
#          POST /governance/move-to-allowed   — flip block->allow
#                                               (guarded override if the
#                                               pattern is Giggso-blocked
#                                               — governance_crud decides).
#          POST /governance/move-to-blocked   — flip allow->block.
#          POST /governance/remove            — remove an entry.
#          All authz is enforced by db/governance_crud.py
#          (_check_scope_authz, validate_override_request) against the
#          `actor` resolved from the verified X-Raven-Identity email via
#          db.policy_queries.get_identity — never trust a client-supplied
#          actor/org_id. PolicyAuthzError -> 403, with the same message
#          governance_crud raises (already descriptive, e.g. "D3: no
#          reason").
# AUDIT LOG:
#   v1.0.0  2026-07-21  Initial — 5 write endpoints.
# =============================================================

import datetime as _dt
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from routers._raven_actor import resolve_actor as _resolve_actor
from routers._raven_identity import verify_ravenhub_identity

router = APIRouter(dependencies=[Depends(verify_ravenhub_identity)])


def _date(s: Optional[str]):
    return _dt.date.fromisoformat(s) if s else None


class ActionResponse(BaseModel):
    ok: bool
    row_id: Optional[str] = None
    message: str


class ApproveRequest(BaseModel):
    scope: str
    provider_pattern: str
    name: Optional[str] = None
    project_id: Optional[str] = None
    user_id: Optional[str] = None
    reason: Optional[str] = None
    valid_until: Optional[str] = None


class BlockRequest(BaseModel):
    scope: str
    domain: str
    name: Optional[str] = None
    severity: Optional[str] = None
    category: Optional[str] = None
    project_id: Optional[str] = None
    user_id: Optional[str] = None
    reason: Optional[str] = None


class MoveToAllowedRequest(BaseModel):
    block_row_id: str
    reason: Optional[str] = None
    valid_until: Optional[str] = None


class MoveToBlockedRequest(BaseModel):
    approve_row_id: str
    severity: str = "HIGH"


class RemoveRequest(BaseModel):
    model: str  # "approved" | "blocked"
    row_id: str


@router.post("/governance/approve", response_model=ActionResponse)
def approve_provider(body: ApproveRequest, email: str = Depends(verify_ravenhub_identity)) -> ActionResponse:
    """Plain allow-list add — never sets overrides_giggso. To permit a
    Giggso-blocked tool, use POST /governance/override instead."""
    from db.engine import get_session
    from db.governance_crud import PolicyAuthzError, add_approved
    with get_session() as s:
        actor, org_id = _resolve_actor(s, email)
        try:
            row = add_approved(
                s, actor=actor, org_id=org_id, scope=body.scope,
                name=(body.name or body.provider_pattern), provider_pattern=body.provider_pattern,
                project_id=body.project_id, user_id=body.user_id,
                reason=body.reason, valid_until=_date(body.valid_until),
            )
        except PolicyAuthzError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
    return ActionResponse(ok=True, row_id=str(row.id), message=f"Approved `{body.provider_pattern}` at {body.scope} scope.")


@router.post("/governance/block", response_model=ActionResponse)
def block_provider(body: BlockRequest, email: str = Depends(verify_ravenhub_identity)) -> ActionResponse:
    from db.engine import get_session
    from db.governance_crud import PolicyAuthzError, add_blacklisted
    with get_session() as s:
        actor, org_id = _resolve_actor(s, email)
        try:
            row = add_blacklisted(
                s, actor=actor, org_id=org_id, scope=body.scope, domain=body.domain,
                name=body.name, severity=body.severity, category=body.category,
                project_id=body.project_id, user_id=body.user_id, reason=body.reason,
            )
        except PolicyAuthzError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
    return ActionResponse(ok=True, row_id=str(row.id), message=f"Blocked `{body.domain}` at {body.scope} scope.")


@router.post("/governance/move-to-allowed", response_model=ActionResponse)
def move_to_allowed_provider(body: MoveToAllowedRequest, email: str = Depends(verify_ravenhub_identity)) -> ActionResponse:
    """Flip a blocked entry to allowed. If the pattern is Giggso-baseline,
    governance_crud routes it through the guarded override automatically
    (reason required) — same as provider_governance.py's flip action."""
    from db.engine import get_session
    from db.governance_crud import PolicyAuthzError, move_to_allowed
    with get_session() as s:
        actor, org_id = _resolve_actor(s, email)
        try:
            was_override = move_to_allowed(
                s, actor=actor, org_id=org_id, block_row_id=body.block_row_id,
                reason=body.reason, valid_until=_date(body.valid_until),
            )
        except PolicyAuthzError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
    extra = " (guarded Giggso override)" if was_override else ""
    return ActionResponse(ok=True, message=f"Moved to allowed{extra}.")


@router.post("/governance/move-to-blocked", response_model=ActionResponse)
def move_to_blocked_provider(body: MoveToBlockedRequest, email: str = Depends(verify_ravenhub_identity)) -> ActionResponse:
    from db.engine import get_session
    from db.governance_crud import PolicyAuthzError, move_to_blocked
    with get_session() as s:
        actor, org_id = _resolve_actor(s, email)
        try:
            move_to_blocked(s, actor=actor, org_id=org_id, approve_row_id=body.approve_row_id, severity=body.severity)
        except PolicyAuthzError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
    return ActionResponse(ok=True, message="Moved to blocked.")


@router.post("/governance/remove", response_model=ActionResponse)
def remove_provider_entry(body: RemoveRequest, email: str = Depends(verify_ravenhub_identity)) -> ActionResponse:
    from db.engine import get_session
    from db.governance_crud import PolicyAuthzError, remove_entry
    from db.models_policy import ApprovedTool, BlacklistedTool
    if body.model not in ("approved", "blocked"):
        raise HTTPException(status_code=422, detail="model must be 'approved' or 'blocked'")
    model = ApprovedTool if body.model == "approved" else BlacklistedTool
    with get_session() as s:
        actor, _org_id = _resolve_actor(s, email)
        try:
            found = remove_entry(s, actor=actor, model=model, row_id=body.row_id)
        except PolicyAuthzError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
    if not found:
        raise HTTPException(status_code=404, detail="Entry not found")
    return ActionResponse(ok=True, message="Removed.")
