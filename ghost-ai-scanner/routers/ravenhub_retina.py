# =============================================================
# FILE: routers/ravenhub_retina.py
# VERSION: 1.0.0
# UPDATED: 2026-09-02
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: RavenHub Card link endpoints on the Patron side.
#
#   POST /retina/link/{patron_token}
#     Links a Patron agent to a RavenHub device token. Called by the
#     Hub admin after issuing a token via POST /api/v1/devices/token/emit.
#     Stores the raven_hub_token_id in the agent's meta.json so the
#     retina assembler can post fingerprints to Hub.
#
#   GET  /retina/link/{patron_token}
#     Returns the current raven_hub_token_id for a Patron agent (for
#     admin verification). Returns "" if not yet linked.
#
#   DELETE /retina/link/{patron_token}
#     Clears the raven_hub_token_id (unlinks the agent from the Hub).
#
# AUTH: standard API_KEY bearer (same as all other Patron API routes).
# DEPENDS: fastapi, pydantic, store.agent_store
# AUDIT LOG:
#   v1.0.0  2026-09-02  Initial. RavenHub Card — Patron side.
# =============================================================

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

router = APIRouter()


def _get_store(request: Request):
    """Pull the AgentStore from the app state (set in api.py startup)."""
    store = getattr(request.app.state, "agent_store", None)
    if store is None:
        raise HTTPException(500, "agent_store not initialised")
    return store


class LinkPayload(BaseModel):
    raven_hub_token_id: str


@router.post("/retina/link/{patron_token}")
async def link_hub_token(
    patron_token: str,
    body: LinkPayload,
    store=Depends(_get_store),
):
    """Store the Hub device token for a Patron agent.

    Call this after POST /api/v1/devices/token/emit on the Hub returns a
    token_id. Pass that token_id here as raven_hub_token_id so the retina
    assembler can begin posting fingerprints for this agent.

    Returns 404 if the patron_token has no meta.json (agent does not exist).
    """
    hub_token = (body.raven_hub_token_id or "").strip()
    if not hub_token:
        raise HTTPException(400, "raven_hub_token_id must not be empty")

    ok = store.set_hub_token_id(patron_token, hub_token)
    if not ok:
        raise HTTPException(404, f"No agent found for patron token {patron_token[:8]!r}")

    return {
        "status": "linked",
        "patron_token": patron_token,
        "raven_hub_token_id": hub_token,
    }


@router.get("/retina/link/{patron_token}")
async def get_hub_token_link(
    patron_token: str,
    store=Depends(_get_store),
):
    """Return the current Hub device token for a Patron agent."""
    hub_token = store.get_hub_token_id(patron_token)
    return {
        "patron_token": patron_token,
        "raven_hub_token_id": hub_token,
        "linked": bool(hub_token),
    }


@router.delete("/retina/link/{patron_token}")
async def unlink_hub_token(
    patron_token: str,
    store=Depends(_get_store),
):
    """Clear the Hub device token for a Patron agent (unlink)."""
    ok = store.set_hub_token_id(patron_token, "")
    if not ok:
        raise HTTPException(404, f"No agent found for patron token {patron_token[:8]!r}")
    return {"status": "unlinked", "patron_token": patron_token}
