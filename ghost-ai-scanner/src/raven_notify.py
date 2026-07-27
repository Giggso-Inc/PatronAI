# =============================================================
# FILE: src/raven_notify.py
# VERSION: 1.0.0
# UPDATED: 2026-07-27
# OWNER: Giggso Inc
# PURPOSE: Phase 5 of the raven<->patron MCP-governance-sync initiative (see
#          MCP_GOVERNANCE_SYNC_PLAN.md at the dashboard repo root). The
#          reverse direction of hub/app/services/patron_sync.py (raven's own
#          outbound module) — patron calling OUT to raven, for exactly one
#          purpose: when a patron admin approves a RavenHub-forwarded MCP
#          flag (routers/raven_enterprise_mcp_flags.py's inbound sync,
#          resolved via db.governance_crud.resolve_raven_flag), notify raven
#          so the SAME decision lands in raven's own org-wide MCP policy
#          allow-list — otherwise raven's mcp-guard.py keeps treating that
#          MCP as unregistered forever, and the same use regenerates a fresh
#          notice every time (a raven MCPGovernanceNotice only dedupes while
#          a prior one is still pending).
#
#          Same never-raises, best-effort contract as patron_sync.py: a
#          raven outage/misconfiguration must never block or roll back the
#          patron-side approval that already happened — this is purely a
#          courtesy notification.
#
#          Config (both required — no-ops with an error if either missing):
#            RAVEN_HUB_BASE_URL   e.g. http://127.0.0.1:8090
#            RAVEN_JWT_SECRET     HS256 signing secret, must match raven's
#                                 hub/app/services/patron_identity.py's
#                                 RAVEN_JWT_SECRET exactly (same shared
#                                 secret already used for the opposite
#                                 direction throughout this integration).
# =============================================================

import json
import os
import time
import urllib.error
import urllib.request

from jose import jwt

_ALGORITHM = "HS256"
_TIMEOUT_SECONDS = 5


def notify_raven_mcp_approved(*, external_ref: str, mcp_name: str, resolved_by: str) -> dict:
    """Tell raven that `mcp_name` was approved for the Project identified by
    `external_ref` (raven's own ComponentGroup.group_id — the same value
    raven originally sent when it synced the Project/flag to patron).

    Args:
        external_ref: raven's group_id for the Project this approval belongs
            to. raven resolves its own org server-side from this — patron
            never needs to know or send raven's org string.
        mcp_name: the raw MCP name being approved (e.g. "gmail") — same
            value stored on RavenFlaggedTool.provider_pattern, NOT the
            `mcp:*:<name>` wrapped form patron writes into its own
            ApprovedTool.domain_pattern (see db.governance_crud's
            _raven_mcp_match_pattern) — raven's own OrgPolicy stores plain
            MCP names, that wrapping is patron-internal only.
        resolved_by: the patron admin's email who clicked Approve — recorded
            as OrgPolicy.updated_by on raven's side for audit.

    Returns:
        {"ok": True} on success, or {"ok": False, "error": str} on failure.
        Never raises: a raven outage or misconfiguration must not block or
        roll back the patron-side approval that triggered this call.
    """
    base_url = os.environ.get("RAVEN_HUB_BASE_URL", "").rstrip("/")
    secret = os.environ.get("RAVEN_JWT_SECRET", "")
    if not base_url or not secret:
        return {"ok": False,
                "error": "Raven callback is not configured (RAVEN_HUB_BASE_URL / RAVEN_JWT_SECRET)."}

    now = int(time.time())
    identity_token = jwt.encode(
        {"email": resolved_by, "iat": now, "exp": now + 60}, secret, algorithm=_ALGORITHM,
    )
    req = urllib.request.Request(
        f"{base_url}/api/v1/patron-callbacks/mcp-approved",
        data=json.dumps({
            "external_ref": external_ref,
            "mcp_name": mcp_name,
            "resolved_by": resolved_by,
        }).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Patron-Identity": identity_token,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_SECONDS) as resp:
            if resp.status >= 300:
                return {"ok": False, "error": f"Raven returned HTTP {resp.status}"}
        return {"ok": True}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "error": f"Raven returned HTTP {exc.code}: {exc.reason}"}
    except Exception as exc:
        return {"ok": False, "error": f"Could not reach Raven: {exc}"}
