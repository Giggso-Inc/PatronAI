# =============================================================
# FILE: src/retina/hub_client.py
# VERSION: 1.0.0
# UPDATED: 2026-09-02
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: HTTP client for the RavenHub Card retina ingest endpoint.
#          Follows the same urllib.request + RAVEN_HUB_URL +
#          X-Raven-Agent pattern used by src/notify/hub_alerts.py.
#
#          POST /api/v1/retina/ingest
#          Auth: token_id in the request body (the Hub device token
#          issued by an admin for this specific (org, host) pair).
#
# DEPENDS: json, os, uuid, urllib (stdlib only)
# AUDIT LOG:
#   v1.0.0  2026-09-02  Initial. RavenHub Card — Patron side.
# =============================================================

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
import uuid

_log = logging.getLogger("marauder-scan.retina.hub_client")

_ASSEMBLER_VERSION = "1.0.0"
_TIMEOUT_SECS      = 8


def post_retina_scan(
    hub_token_id: str,
    retina_hash: str,
    dimensions: dict[str, list[str]],
    hub_url: str | None = None,
    agent_key: str | None = None,
) -> bool:
    """POST a retina scan to the RavenHub Card ingest endpoint.

    hub_token_id: the device token issued by the Hub admin for this machine.
    retina_hash: 64-char hex SHA-256 produced by normaliser.compute_hash().
    dimensions:  normalised D1-D7 dict (already normalised, not raw).
    hub_url:     overrides RAVEN_HUB_URL env var (useful in tests).
    agent_key:   overrides RAVEN_AGENT_KEY env var.

    Returns True on HTTP 200, False on any error (never raises).
    """
    base = (hub_url or os.environ.get("RAVEN_HUB_URL", "")).rstrip("/")
    if not base:
        _log.debug("RAVEN_HUB_URL not set — retina ingest skipped")
        return False
    if not hub_token_id:
        _log.debug("hub_token_id empty — retina ingest skipped")
        return False

    key = agent_key or os.environ.get("RAVEN_AGENT_KEY", "")
    scan_id = str(uuid.uuid4())

    body = {
        "token_id":          hub_token_id,
        "scan_id":           scan_id,
        "assembler_version": _ASSEMBLER_VERSION,
        "retina_hash":       retina_hash,
        "dimensions":        dimensions,
        "schema_version":    "1",
    }

    try:
        req = urllib.request.Request(
            f"{base}/api/v1/retina/ingest",
            data=json.dumps(body).encode(),
            method="POST",
            headers={
                "Content-Type": "application/json",
                **({"X-Raven-Agent": key} if key else {}),
            },
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT_SECS) as resp:
            # Accept any 2xx (Hub may return 201 Created on first ingest).
            ok = 200 <= resp.status < 300
            if not ok:
                _log.warning("retina ingest HTTP %s for token %s",
                             resp.status, hub_token_id[:8])
            return ok
    except urllib.error.HTTPError as e:
        _log.warning("retina ingest HTTP error %s for token %s: %s",
                     e.code, hub_token_id[:8], e.reason)
    except Exception as e:
        _log.warning("retina ingest failed for token %s: %s",
                     hub_token_id[:8], e)
    return False
