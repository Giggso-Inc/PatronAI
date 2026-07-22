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
#          ADMIN CHECK (2026-07-22, was TEMP as of 2026-07-21): granting
#          is_admin=true or removing a user now requires the CALLER to
#          already be a real policy-DB org admin (routers._raven_actor.
#          resolve_actor + actor.is_org_admin) — closing the earlier
#          self-escalation hole (any authenticated caller could grant
#          themselves admin). Deliberately NOT routed through ravenhub.
#          py's _resolve_is_admin — that resolver was itself relaxed to
#          always return True as a separate, disclosed TEMP measure, and
#          using it here would silently defeat this gate. Listing users
#          (GET) and adding/editing a non-admin user stay open, matching
#          the codebase's existing disclosed posture elsewhere.
#
#          POLICY-DB SYNC (2026-07-22): this S3 users.json store and the
#          policy DB's `users.is_org_admin` column (src/db/models_identity
#          .py) used to only be linked once, at seed time (src/db/seeding
#          .py's upsert_users backfills is_org_admin FROM this store) —
#          never kept in sync afterward, so editing is_admin here had no
#          effect on Provider Governance's org-admin gate
#          (governance_crud._check_scope_authz). Every write below now
#          also updates the matching policy-DB row (by email) if one
#          exists, so this becomes the real, live control for both. It
#          never CREATES a new policy-DB row (that needs an org_id this
#          endpoint has no basis to guess) — only syncs an existing one.
#          This only covers this REST path; the Streamlit users.py tab
#          writes S3 directly and is not wired to this sync.
#
#          WELCOME EMAIL: the Streamlit tab optionally sends a real SES
#          welcome email on add. That's a live external side effect this
#          REST endpoint does NOT trigger unless the caller explicitly
#          opts in via `notify: true` — default is False, opposite of the
#          Streamlit tab's default, since a REST caller shouldn't be able
#          to accidentally email a real person.
# AUDIT LOG:
#   v1.0.0  2026-07-21  Initial — 4 endpoints.
#   v1.1.0  2026-07-22  Admin gate on grant-admin/remove; policy-DB
#                       is_org_admin sync on write.
# =============================================================

import os
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from routers._raven_actor import resolve_actor as _resolve_actor
from routers._raven_identity import verify_ravenhub_identity

router = APIRouter(dependencies=[Depends(verify_ravenhub_identity)])


def _store():
    from store.users_store import UsersStore
    bucket = os.environ.get("MARAUDER_SCAN_BUCKET", "")
    if not bucket:
        raise HTTPException(status_code=503, detail="MARAUDER_SCAN_BUCKET not configured")
    return UsersStore(bucket, os.environ.get("AWS_REGION", "us-east-1"))


def _require_caller_is_org_admin(caller_email: str) -> None:
    """Real policy-DB admin check (NOT ravenhub.py's relaxed
    _resolve_is_admin) — the caller must already be a recognized,
    is_org_admin=True policy-DB user. resolve_actor itself 403s with
    "isn't a policy-DB user yet" if the caller has no policy-DB row at
    all, which is correct here too."""
    from db.engine import get_session
    with get_session() as s:
        actor, _org_id = _resolve_actor(s, caller_email)
        if not actor.is_org_admin:
            raise HTTPException(status_code=403, detail="Only an org admin may grant admin access or remove a user.")


def _sync_policy_db_admin(target_email: str, is_admin: bool) -> None:
    """Mirror an S3 roster is_admin change onto the matching policy-DB
    User row, if one exists. Never creates a row (no org_id to attach a
    brand-new one to safely) — only keeps an existing one's
    is_org_admin in step with this store."""
    from sqlalchemy import select
    from db.engine import get_session
    from db.models_identity import User
    key = target_email.strip().lower()
    with get_session() as s:
        u = s.execute(select(User).where(User.email == key)).scalar_one_or_none()
        if u is not None and u.is_org_admin != is_admin:
            u.is_org_admin = is_admin
            s.commit()


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
    form and inline Edit — UsersStore.upsert is idempotent per email).

    Gated on any CHANGE to is_admin, not just a new True value — a caller
    editing role only (or a client that omits is_admin, which defaults to
    False) must not be able to silently demote an existing admin. Only a
    real state change requires the caller to already be an org admin;
    re-saving the same is_admin value (grant or plain) stays open."""
    store = _store()
    existing = store.get(body.email)
    existing_is_admin = bool(existing.get("is_admin")) if existing else False
    if body.is_admin != existing_is_admin:
        _require_caller_is_org_admin(email)

    ok = store.upsert(body.email, body.role, body.is_admin, added_by=email)
    if not ok:
        raise HTTPException(status_code=400, detail="Add/update failed — check email format and role.")

    _sync_policy_db_admin(body.email, body.is_admin)

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
    _require_caller_is_org_admin(email)

    store = _store()
    users = store.read_all()
    old_rec = users.get(target_email.strip().lower())
    ok = store.remove(target_email)
    if not ok:
        raise HTTPException(status_code=400, detail="Remove failed.")

    _sync_policy_db_admin(target_email, False)

    from dashboard.ui.audit import write_user_action
    write_user_action(email, "remove", target_email.strip().lower(), old_record=old_rec, new_record=None)
    return ActionResponse(ok=True, message=f"Removed {target_email.strip().lower()}.")
