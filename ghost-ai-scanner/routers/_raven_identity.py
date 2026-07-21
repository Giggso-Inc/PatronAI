# =============================================================
# FILE: routers/_raven_identity.py
# VERSION: 1.0.0
# UPDATED: 2026-07-21
# OWNER: Giggso Inc
# PURPOSE: Shared caller-identity verification for RavenHub routers
#          (extracted from routers/ravenhub.py v1.4.0 so the new
#          governance routers reuse the SAME implementation instead
#          of a second copy — PR#9 review, C1).
#          Verifies a raven-enterprise-issued JWT (X-Raven-Identity
#          header, HS256, RAVEN_JWT_SECRET == raven-enterprise's
#          SECRET_KEY) and returns the verified `email` claim.
#          Separate header from Authorization on purpose: Authorization
#          stays reserved for api.py's shared API_KEY (service-level)
#          check; this is the user-level check, layered on top of it,
#          not a replacement for it.
# SCOPE: import this into a router's own APIRouter(dependencies=[...])
#        to enforce it on that router only. Never attach to `app` in
#        api.py directly, or it stops being router-scoped.
# AUDIT LOG:
#   v1.0.0  2026-07-21  Extracted from ravenhub.py v1.4.0 (no behavior
#                       change) so ravenhub_governance_* routers can
#                       reuse it without duplicating the check.
# =============================================================

import os
from typing import Optional

from fastapi import Header, HTTPException
from jose import JWTError, jwt

# Must match raven-enterprise's app/core/config.py SECRET_KEY/ALGORITHM
# exactly, or every token fails to verify. No centralized settings module
# exists in this repo (see ravenhub.py's own note) — inline os.environ.get()
# is the established pattern here.
_RAVEN_JWT_SECRET = os.environ.get("RAVEN_JWT_SECRET", "")
_RAVEN_JWT_ALGORITHM = "HS256"


def verify_ravenhub_identity(
    x_raven_identity: Optional[str] = Header(default=None, alias="X-Raven-Identity"),
) -> str:
    """Decode + verify the raven-enterprise-issued JWT and return its
    verified `email` claim. Do NOT reintroduce a client-supplied
    email/viewer_email/actor query param for identity anywhere this is
    used — that was C1 in the PR#9 review."""
    if not _RAVEN_JWT_SECRET:
        raise HTTPException(status_code=503, detail="RAVEN_JWT_SECRET not configured")
    if not x_raven_identity:
        raise HTTPException(status_code=401, detail="Missing X-Raven-Identity token")
    try:
        payload = jwt.decode(x_raven_identity, _RAVEN_JWT_SECRET, algorithms=[_RAVEN_JWT_ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired identity token")
    email = payload.get("email")
    if not email:
        raise HTTPException(status_code=401, detail="Identity token missing email claim")
    return str(email).strip().lower()
