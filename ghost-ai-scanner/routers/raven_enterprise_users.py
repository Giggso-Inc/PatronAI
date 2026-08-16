# =============================================================
# FILE: routers/raven_enterprise_users.py
# VERSION: 1.0.0
# UPDATED: 2026-08-16
# OWNER: Giggso Inc
# PURPOSE: Upsert a patron identity for a RavenHub user, and set their
#          org-admin flag from the RavenHub role. Sibling of
#          routers/raven_enterprise_projects.py — same service-to-service
#          trust model, same house style — but for people rather than
#          projects.
#
#          WHY THIS EXISTS AT ALL: nothing used to create a patron identity
#          for a RavenHub-invited user, and patron fails CLOSED on unknown
#          emails — resolve_actor 403s with "isn't a policy-DB user yet",
#          and _resolve_is_admin ends at _env_is_admin's "email is not on
#          the access list". So an invited user got 403 with no data on
#          Shadow AI and Controls, not degraded access. Only the org owner
#          (provisioned at bootstrap) ever escaped that.
#
#          WHY NOT POST /ravenhub/users: that route writes S3 BEFORE any DB
#          sync, and its DB helper _sync_policy_db_admin is UPDATE-only —
#          its own docstring says "Never creates a row". Adding a brand-new
#          user through it produces an S3 entry with no policy-DB row,
#          which is the exact failure this endpoint exists to prevent. It
#          also 403s a non-org-admin caller whenever is_admin changes,
#          which the Hub's service identity is not.
#
#          ORG COMES FROM THE PAYLOAD, NOT THE CALLER — deliberately, and
#          this is the one place this router differs from its sibling. The
#          obvious move is _resolve_actor(s, email) as raven_enterprise_
#          projects.py does, but that creates a chicken-and-egg: it raises
#          403 for an actor who is not already a patron user, so the Hub
#          could only sync a user if the identity it signs as had itself
#          already been synced. On the invite-accept path the natural actor
#          is the inviter, who may never have been; in a fresh org nobody
#          has been. The FIRST sync would fail, permanently. Trust is
#          already established by two shared secrets (api.py's bearer
#          API_KEY at the service level, and the X-Raven-Identity JWT at
#          the user level), and the Hub is authoritative for org
#          membership, so the org is taken from the request.
#          TRADE-OFF, STATED: this endpoint does NOT verify the caller
#          belongs to the org it writes to. That check was doing nothing
#          useful here — the Hub is the only caller and authenticates as a
#          service — but it is a conscious choice, not an omission.
#          Lookup is STRICT (404 on an unknown slug), never ensure_org, so
#          a typo cannot silently create an org.
#
#          IDEMPOTENT: re-syncing the same user returns the existing row
#          and re-applies is_org_admin. Safe to retry, and safe to call on
#          a no-op role change. Refuses (409) if the email already belongs
#          to a DIFFERENT patron org rather than cross-linking someone
#          else's identity.
#
#          NOT TOUCHED: S3 users.json (the legacy read model behind GET
#          /ravenhub/users and the Streamlit UI), _resolve_is_admin,
#          _admin_shim. A user synced here will NOT appear in the Streamlit
#          roster. Known and accepted — see SPEC-role-sync §4.
# AUDIT LOG:
#   v1.0.0  2026-08-16  Initial — user upsert + admin flag (SPEC-role-sync Phase 2).
# =============================================================

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr

from routers._raven_identity import verify_ravenhub_identity

router = APIRouter(dependencies=[Depends(verify_ravenhub_identity)])


class SyncUserRequest(BaseModel):
    email: EmailStr
    org_slug: str
    is_admin: bool = False
    display_name: str | None = None


class SyncUserOut(BaseModel):
    ok: bool
    user_id: str
    email: str
    is_org_admin: bool
    created: bool


def _require_db() -> None:
    import os
    if not os.environ.get("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="User sync requires the policy database (DATABASE_URL not set).")


@router.post("/users/sync", response_model=SyncUserOut)
def sync_user_endpoint(
    body: SyncUserRequest,
    email: str = Depends(verify_ravenhub_identity),
) -> SyncUserOut:
    _require_db()
    from sqlalchemy import select

    from db.engine import get_session
    from db.governance_crud import get_or_create_user_for_sync
    from db.models_identity import Org, User

    with get_session() as s:
        org = s.execute(select(Org).where(Org.slug == body.org_slug)).scalar_one_or_none()
        if org is None:
            raise HTTPException(status_code=404, detail=f"No patron org with slug '{body.org_slug}'")

        # Captured BEFORE the upsert so the Hub can log create-vs-update. Uses the
        # same normalisation get_or_create_user_for_sync applies, or a
        # differently-cased address would report created=True on every sync.
        norm_email = str(body.email).strip().lower()
        existed = s.execute(
            select(User.id).where(User.email == norm_email)
        ).scalar_one_or_none() is not None

        try:
            user = get_or_create_user_for_sync(s, org_id=org.id, email=norm_email)
            if user.is_org_admin != body.is_admin:
                user.is_org_admin = body.is_admin
            # Only fill a missing display name — never overwrite one the user or
            # an earlier seed already set.
            if body.display_name and not user.display_name:
                user.display_name = body.display_name
            # REQUIRED: get_or_create_user_for_sync only flush()es, and
            # get_session() does not commit on context exit. The existing caller
            # in raven_enterprise_projects.py only persists by accident of
            # add_project_member_from_sync committing afterwards. Without this
            # line the row is silently lost.
            s.commit()
        except ValueError as exc:
            s.rollback()
            raise HTTPException(status_code=409, detail=str(exc))
        except HTTPException:
            raise
        except Exception as exc:
            s.rollback()
            raise HTTPException(status_code=400, detail=f"user sync failed: {exc}")

        return SyncUserOut(
            ok=True,
            user_id=str(user.id),
            email=user.email,
            is_org_admin=bool(user.is_org_admin),
            created=not existed,
        )
