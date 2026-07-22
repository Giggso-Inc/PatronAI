# =============================================================
# FILE: routers/ravenhub_users.py
# VERSION: 1.0.0
# UPDATED: 2026-07-21
# OWNER: Giggso Inc
# PURPOSE: REST export of dashboard/ui/tabs/users.py — list/add/edit/remove
#          users in the tenant's S3-backed users.json (store.users_store.
#          UsersStore — the SAME file routers/ravenhub.py's _s3_is_admin
#          reads for admin resolution). Requires the verified
#          X-Raven-Identity JWT, same as every other ravenhub router.
#
#          ADMIN CHECK — TEMP (2026-07-21): same decision as ravenhub.py /
#          ravenhub_projects.py — the Streamlit tab's admin-only gate lived
#          entirely in the render layer (`render(email)` — caller already
#          gated), not inside UsersStore itself, so there's no internal
#          guard to bypass here; any authenticated caller can read/write.
#          TODO: once FE role routing is integrated, add a real
#          _resolve_is_admin-style check before allowing writes.
#
#          WELCOME EMAIL: the Streamlit tab optionally sends a real SES
#          welcome email on add. That's a live external side effect this
#          REST endpoint does NOT trigger unless the caller explicitly
#          opts in via `notify: true` — default is False, opposite of the
#          Streamlit tab's default, since a REST caller shouldn't be able
#          to accidentally email a real person.
# AUDIT LOG:
#   v1.0.0  2026-07-21  Initial — 4 endpoints.
# =============================================================

import os
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from routers._raven_identity import verify_ravenhub_identity

router = APIRouter(dependencies=[Depends(verify_ravenhub_identity)])


def _store():
    from store.users_store import UsersStore
    bucket = os.environ.get("MARAUDER_SCAN_BUCKET", "")
    if not bucket:
        raise HTTPException(status_code=503, detail="MARAUDER_SCAN_BUCKET not configured")
    return UsersStore(bucket, os.environ.get("AWS_REGION", "us-east-1"))


class UserRecord(BaseModel):
    email: str
    role: str
    is_admin: bool
    added_at: Optional[str] = None
    added_by: Optional[str] = None


class UsersResponse(BaseModel):
    users: list[UserRecord]


class UpsertUserRequest(BaseModel):
    email: str
    role: str  # "exec" | "manager" | "support"
    is_admin: bool = False
    notify: bool = False


class ActionResponse(BaseModel):
    ok: bool
    message: str


@router.get("/users", response_model=UsersResponse)
def list_users_endpoint(email: str = Depends(verify_ravenhub_identity)) -> UsersResponse:
    """Every user in the tenant's users.json — mirrors users.py's table."""
    store = _store()
    users = store.read_all()
    return UsersResponse(users=[UserRecord(email=em, **rec) for em, rec in sorted(users.items())])


@router.post("/users", response_model=ActionResponse)
def upsert_user_endpoint(body: UpsertUserRequest, email: str = Depends(verify_ravenhub_identity)) -> ActionResponse:
    """Add or edit a user (same upsert path as the Streamlit tab's Add
    form and inline Edit — UsersStore.upsert is idempotent per email)."""
    store = _store()
    ok = store.upsert(body.email, body.role, body.is_admin, added_by=email)
    if not ok:
        raise HTTPException(status_code=400, detail="Add/update failed — check email format and role.")

    from dashboard.ui.audit import write_user_action
    write_user_action(email, "upsert", body.email.strip().lower(), old_record=None,
                       new_record={"role": body.role, "is_admin": body.is_admin})

    if body.notify:
        try:
            from notify.email import send_welcome
            send_welcome(recipient=body.email.strip().lower(), name=body.email.split("@")[0],
                         role=body.role, added_by=email)
        except Exception:
            pass  # best-effort, same as the Streamlit tab's own try/except
    return ActionResponse(ok=True, message=f"Saved {body.email.strip().lower()}.")


@router.delete("/users/{target_email}", response_model=ActionResponse)
def remove_user_endpoint(target_email: str, email: str = Depends(verify_ravenhub_identity)) -> ActionResponse:
    store = _store()
    users = store.read_all()
    old_rec = users.get(target_email.strip().lower())
    ok = store.remove(target_email)
    if not ok:
        raise HTTPException(status_code=400, detail="Remove failed.")

    from dashboard.ui.audit import write_user_action
    write_user_action(email, "remove", target_email.strip().lower(), old_record=old_rec, new_record=None)
    return ActionResponse(ok=True, message=f"Removed {target_email.strip().lower()}.")
