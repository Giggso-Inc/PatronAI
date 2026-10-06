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

import os
import re

from fastapi import APIRouter, Depends, HTTPException, Path
from pydantic import BaseModel

from store.agent_store import AgentStore

# patron_token is always a UUID (hex digits and hyphens). Enforcing this
# here prevents path-traversal attacks where a caller passes "../../../..."
# to read or overwrite arbitrary S3 keys under config/HOOK_AGENTS/.
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


def _validate_token(patron_token: str) -> str:
    if not _UUID_RE.match(patron_token):
        raise HTTPException(400, "patron_token must be a valid UUID")
    return patron_token

router = APIRouter()


def _get_store() -> AgentStore:
    """Build the AgentStore from env vars for the retina link endpoints.

    Mirrors api.py's own _get_store() pattern. app.state.agent_store is
    never populated at startup, so pulling from there always 500s; this
    builds the store directly instead.

    Returns:
        AgentStore: Backed by MARAUDER_SCAN_BUCKET in AWS_REGION.

    Raises:
        HTTPException: 503 if MARAUDER_SCAN_BUCKET is not configured — matches
            api.py's own _get_store() for the same condition.
    """
    bucket = os.environ.get("MARAUDER_SCAN_BUCKET", "")
    if not bucket:
        raise HTTPException(503, "MARAUDER_SCAN_BUCKET not configured")
    region = os.environ.get("AWS_REGION", "us-east-1")
    return AgentStore(bucket, region)


class LinkPayload(BaseModel):
    raven_hub_token_id: str
    raven_hub_token_secret: str = ""  # proof secret paired with token_id; required for retina scanning


@router.post("/retina/link/{patron_token}")
async def link_hub_token(
    patron_token: str = Depends(_validate_token),
    body: LinkPayload = ...,
    store=Depends(_get_store),
):
    """Store the Hub device token (and proof secret) for a Patron agent.

    Call this after POST /api/v1/devices/token/emit on the Hub returns a
    token_id + token_secret. Both must be stored so the retina assembler
    can authenticate its scan POSTs to the Hub.

    Returns 404 if the patron_token has no meta.json (agent does not exist).
    """
    hub_token = (body.raven_hub_token_id or "").strip()
    if not hub_token:
        raise HTTPException(400, "raven_hub_token_id must not be empty")
    hub_secret = (body.raven_hub_token_secret or "").strip()
    if not hub_secret:
        raise HTTPException(400, "raven_hub_token_secret must not be empty")

    ok = store.set_hub_token_id(patron_token, hub_token, hub_token_secret=hub_secret)
    if not ok:
        raise HTTPException(404, f"No agent found for patron token {patron_token[:8]!r}")

    return {
        "status": "linked",
        "patron_token": patron_token,
        "raven_hub_token_id": hub_token,
        "raven_hub_token_secret_set": True,
    }


@router.get("/retina/link/{patron_token}")
async def get_hub_token_link(
    patron_token: str = Depends(_validate_token),
    store=Depends(_get_store),
):
    """Return whether this Patron agent is linked to a Hub device token.

    Does NOT return the raw token — callers can only verify link state, not
    retrieve the credential. A bearer token disclosed here would allow any
    holder of the org-wide API key to forge fingerprint scans on behalf of
    any device.
    """
    hub_token = store.get_hub_token_id(patron_token)
    hub_secret = store.get_hub_token_secret(patron_token)
    return {
        "patron_token": patron_token,
        "linked": bool(hub_token),
        "raven_hub_token_id": hub_token,
        "raven_hub_token_secret_set": bool(hub_secret),
    }


@router.delete("/retina/link/{patron_token}")
async def unlink_hub_token(
    patron_token: str = Depends(_validate_token),
    store=Depends(_get_store),
):
    """Clear the Hub device token for a Patron agent (unlink)."""
    ok = store.set_hub_token_id(patron_token, "")
    if not ok:
        raise HTTPException(404, f"No agent found for patron token {patron_token[:8]!r}")
    return {"status": "unlinked", "patron_token": patron_token}
