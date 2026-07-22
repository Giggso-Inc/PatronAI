# =============================================================
# FILE: routers/ravenhub_governance_writes_overrides.py
# VERSION: 1.0.0
# UPDATED: 2026-07-21
# OWNER: Giggso Inc
# PURPOSE: The two GUARDED governance actions — permitting a tool that's
#          blocked at a wider scope. Deliberately separate from
#          ravenhub_governance_writes_lists.py's plain approve/block so
#          neither can be triggered by a stray boolean flag on a more
#          generic endpoint.
#          POST /governance/override       — permit a Giggso-baseline
#                                             tool at org/project/user
#                                             scope (org-admin only,
#                                             capped x0.5/x0.6/x0.7,
#                                             band-floored, reason
#                                             required, 90-day expiry).
#                                             Mirrors provider_governance
#                                             .py:_override_section().
#          POST /governance/deny-override   — permit a tool an org/
#                                             project deny blocked, at a
#                                             NARROWER project/user scope
#                                             (org-admin only, same
#                                             guards). Mirrors
#                                             _deny_override_section().
#          Both call straight into db/governance_crud.py — the guard
#          logic (org-admin check, reason+approver+expiry validation,
#          the Giggso floor never being reachable via deny-override) is
#          NOT reimplemented here.
# AUDIT LOG:
#   v1.0.0  2026-07-21  Initial — 2 write endpoints.
# =============================================================

import datetime as _dt
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from routers._raven_actor import resolve_actor as _resolve_actor
from routers._raven_identity import verify_ravenhub_identity

router = APIRouter(dependencies=[Depends(verify_ravenhub_identity)])

_DEFAULT_EXPIRY_DAYS = 90


class ActionResponse(BaseModel):
    ok: bool
    row_id: Optional[str] = None
    message: str


class OverrideRequest(BaseModel):
    scope: str  # "org" | "project" | "user"
    provider_pattern: str
    reason: str
    project_id: Optional[str] = None
    user_id: Optional[str] = None


class DenyOverrideRequest(BaseModel):
    scope: str  # "project" | "user" only
    provider_pattern: str
    reason: str
    project_id: Optional[str] = None
    user_id: Optional[str] = None


@router.post("/governance/override", response_model=ActionResponse)
def override_giggso_baseline(body: OverrideRequest, email: str = Depends(verify_ravenhub_identity)) -> ActionResponse:
    """Permit a Giggso-blocked tool at the given scope. Org-admin only —
    enforced inside add_approved/validate_override_request, not here."""
    from db.engine import get_session
    from db.governance_crud import PolicyAuthzError, add_approved
    with get_session() as s:
        actor, org_id = _resolve_actor(s, email)
        try:
            row = add_approved(
                s, actor=actor, org_id=org_id, scope=body.scope,
                name=body.provider_pattern, provider_pattern=body.provider_pattern,
                project_id=body.project_id, user_id=body.user_id,
                overrides_giggso=True, reason=body.reason,
                valid_until=_dt.date.today() + _dt.timedelta(days=_DEFAULT_EXPIRY_DAYS),
            )
        except PolicyAuthzError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
    return ActionResponse(
        ok=True, row_id=str(row.id),
        message=f"Giggso override recorded for `{body.provider_pattern}` at {body.scope} scope "
                f"(expires {_DEFAULT_EXPIRY_DAYS}d).",
    )


@router.post("/governance/deny-override", response_model=ActionResponse)
def deny_override_provider(body: DenyOverrideRequest, email: str = Depends(verify_ravenhub_identity)) -> ActionResponse:
    """Permit, at project/user scope, a tool a wider scope denied.
    Org-admin only; never reaches a Giggso-blocked tool (D4) — that's
    enforced inside grant_deny_override, not here."""
    from db.engine import get_session
    from db.governance_crud import PolicyAuthzError, grant_deny_override
    with get_session() as s:
        actor, org_id = _resolve_actor(s, email)
        try:
            row = grant_deny_override(
                s, actor=actor, org_id=org_id, scope=body.scope,
                provider_pattern=body.provider_pattern,
                project_id=body.project_id, user_id=body.user_id, reason=body.reason,
                valid_until=_dt.date.today() + _dt.timedelta(days=_DEFAULT_EXPIRY_DAYS),
            )
        except PolicyAuthzError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
    return ActionResponse(
        ok=True, row_id=str(row.id),
        message=f"Deny-override recorded for `{body.provider_pattern}` at {body.scope} scope "
                f"(expires {_DEFAULT_EXPIRY_DAYS}d).",
    )
