# =============================================================
# FILE: routers/_raven_actor.py
# VERSION: 1.0.0
# UPDATED: 2026-07-21
# OWNER: Giggso Inc
# PURPOSE: Resolve a verified X-Raven-Identity email (see
#          routers/_raven_identity.py) to a policy-DB actor —
#          shared by every ravenhub_governance_* router (reads and
#          writes alike), so there's one implementation, not several.
#          NEVER accept an actor/org_id from the client — always
#          resolve it server-side from the verified email.
# AUDIT LOG:
#   v1.0.0  2026-07-21  Initial — extracted so writes routers don't
#                       depend on the reads router for this.
# =============================================================

from fastapi import HTTPException


def resolve_actor(session, email: str):
    """Resolve the verified email to a policy-DB (User, org_id) pair, or
    403 — mirrors provider_governance.py's own "isn't a policy-DB user
    yet" guard, just as an HTTP status instead of a Streamlit warning."""
    from db.policy_queries import get_identity
    actor, org_id, _projects = get_identity(session, email)
    if actor is None or org_id is None:
        raise HTTPException(status_code=403, detail=f"'{email}' isn't a policy-DB user yet")
    return actor, org_id
