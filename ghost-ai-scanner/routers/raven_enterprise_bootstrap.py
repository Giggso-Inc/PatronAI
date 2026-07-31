# =============================================================
# FILE: routers/raven_enterprise_bootstrap.py
# PURPOSE: Hub-driven first-run provisioning for PatronAI org admin.
# Auth: X-Bootstrap-Token only (intentionally no bearer Depends(_auth)).
# =============================================================

from __future__ import annotations

import os
import secrets
from typing import Any

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy import select

from db.engine import get_session
from db.models_identity import Org, User
from db.seeding import _display_name, ensure_org

router = APIRouter()


class ProvisionAdminRequest(BaseModel):
    org_slug: str
    display_name: str
    s3_bucket: str
    owner_email: EmailStr
    owner_name: str = ""


def _verify_bootstrap_token(token: str | None) -> None:
    """Require X-Bootstrap-Token to match BOOTSTRAP_INTERNAL_TOKEN (constant-time)."""
    expected = os.environ.get("BOOTSTRAP_INTERNAL_TOKEN", "").strip()
    if not expected:
        raise HTTPException(status_code=503, detail="Bootstrap token not configured")
    if not token or not secrets.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="Invalid bootstrap token")


def _assert_org_bootstrap_open(session, org: Org) -> None:
    """Reject when this org already has an org admin — one-time first-run control."""
    admin = session.execute(
        select(User).where(User.org_id == org.id, User.is_org_admin.is_(True))
    ).scalar_one_or_none()
    if admin is not None:
        raise HTTPException(
            status_code=410,
            detail="Bootstrap already completed — org admin already exists",
        )


@router.post("/bootstrap/provision-admin")
def provision_admin(
    body: ProvisionAdminRequest,
    x_bootstrap_token: str | None = Header(default=None, alias="X-Bootstrap-Token"),
) -> dict[str, Any]:
    """Create/ensure org and first org admin. Hub-only; disabled once an admin exists for the org."""
    _verify_bootstrap_token(x_bootstrap_token)
    slug = body.org_slug.strip().lower()
    email = body.owner_email.strip().lower()

    with get_session() as session:
        org = ensure_org(
            session,
            slug=slug,
            display_name=body.display_name or slug,
            s3_bucket=body.s3_bucket or slug,
        )
        _assert_org_bootstrap_open(session, org)

        user = session.execute(
            select(User).where(User.email == email)
        ).scalar_one_or_none()
        if user is None:
            user = User(
                org_id=org.id,
                email=email,
                display_name=body.owner_name or _display_name(email),
                is_org_admin=True,
            )
            session.add(user)
        else:
            if user.org_id != org.id:
                raise HTTPException(
                    status_code=409,
                    detail=f"Email {email} already belongs to a different patron org",
                )
            user.is_org_admin = True
            if body.owner_name:
                user.display_name = body.owner_name
        session.commit()
        return {"ok": True, "org_id": str(org.id), "user_id": str(user.id), "email": email}
