# =============================================================
# FILE: src/retina/hub_client.py
# VERSION: 1.0.0
# UPDATED: 2026-09-02
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: HTTP client for the RavenHub Card retina ingest endpoint.
#          Uses RAVEN_HUB_URL plus per-device proof secret auth.
#
#          POST /api/v1/retina/ingest
#          Auth: token_id in the request body plus X-Raven-Device-Secret.
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
from typing import Callable

_log = logging.getLogger("marauder-scan.retina.hub_client")

_ASSEMBLER_VERSION = "1.2.0"  # keep in sync with main.py VERSION comment
_TIMEOUT_SECS      = 8
_DEVICE_SECRET_HEADER = "X-Raven-Device-Secret"


def renew_device_token(
    hub_token_id: str,
    hub_url: str | None = None,
    store_token_fn: Callable[[str], None] | None = None,
) -> str | None:
    """POST /api/v1/devices/token/renew — called when ingest returns 401.

    hub_token_id: the expired (or expiring) device token id.
    hub_url:      overrides RAVEN_HUB_URL env var.
    store_token_fn: optional callback(new_token_id) to persist the new token.
                    Caller is responsible for also updating the token secret
                    via the link endpoint if needed.

    Returns the new token_id on success, None on revocation (403) or error.
    Revocation (403 with 'access_revoked') means the user is no longer in the
    workforce — Patron should surface this to the developer and stop scanning.
    """
    base = (hub_url or os.environ.get("RAVEN_HUB_URL", "")).rstrip("/")
    if not base or not hub_token_id:
        return None

    try:
        body = json.dumps({"token_id": hub_token_id}).encode()
        req = urllib.request.Request(
            f"{base}/api/v1/devices/token/renew",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT_SECS) as resp:
            if 200 <= resp.status < 300:
                data = json.loads(resp.read().decode())
                new_id = data.get("token_id", "")
                if new_id and store_token_fn:
                    store_token_fn(new_id)
                _log.info("retina token renewed: %s → %s",
                          hub_token_id[:8], new_id[:8] if new_id else "?")
                return new_id
    except urllib.error.HTTPError as e:
        if e.code == 403:
            _log.warning("retina token renewal denied (access revoked) for %s",
                         hub_token_id[:8])
        else:
            _log.warning("retina token renewal HTTP %s for %s: %s",
                         e.code, hub_token_id[:8], e.reason)
    except Exception as e:
        _log.warning("retina token renewal failed for %s: %s", hub_token_id[:8], e)
    return None


def post_retina_scan(
    hub_token_id: str,
    hub_token_secret: str,
    retina_hash: str,
    dimensions: dict[str, list[str]],
    hub_url: str | None = None,
    agent_key: str | None = None,
    store_token_fn: Callable[[str], None] | None = None,
    device_name: str | None = None,
    hardware_uid: str | None = None,
    os_version: str | None = None,
) -> bool:
    """POST a retina scan to the RavenHub Card ingest endpoint.

    hub_token_id: the device token id issued by the Hub admin for this machine.
    hub_token_secret: the one-time per-device proof secret paired with token_id.
    retina_hash: 64-char hex SHA-256 produced by normaliser.compute_hash().
    dimensions:  normalised D1-D7 dict (already normalised, not raw).
    hub_url:     overrides RAVEN_HUB_URL env var (useful in tests).
    agent_key:   optional legacy X-Raven-Agent header for deployments that log it.
    store_token_fn: optional callback(new_token_id) — called when the token is
                    renewed mid-scan so the caller can persist the new id.

    Returns True on any 2xx, False on any error (never raises).
    On 401 (expired token), automatically attempts renewal once and retries.
    """
    base = (hub_url or os.environ.get("RAVEN_HUB_URL", "")).rstrip("/")
    if not base:
        _log.debug("RAVEN_HUB_URL not set — retina ingest skipped")
        return False
    if not hub_token_id:
        _log.debug("hub_token_id empty — retina ingest skipped")
        return False
    if not hub_token_secret:
        _log.debug("hub_token_secret empty — retina ingest skipped")
        return False

    key = agent_key or os.environ.get("RAVEN_AGENT_KEY", "")

    # Licence gate — skip silently when the org's licence has lapsed.
    try:
        from notify.hub_licence_gate import note_error, should_skip
    except ImportError:
        try:
            from src.notify.hub_licence_gate import note_error, should_skip
        except ImportError:
            note_error = None
            should_skip = None
    if should_skip is not None and should_skip(base, key):
        return False

    def _do_ingest(token_id: str) -> bool:
        scan_id = str(uuid.uuid4())
        body = {
            "token_id":          token_id,
            "scan_id":           scan_id,
            "assembler_version": _ASSEMBLER_VERSION,
            "retina_hash":       retina_hash,
            "dimensions":        dimensions,
            "schema_version":    "1",
        }
        # Device metadata — only include when present so older Hub versions
        # that don't know these fields are unaffected (they're Optional on
        # the Hub's Pydantic model).
        if device_name:
            body["device_name"] = device_name
        if hardware_uid:
            body["hardware_uid"] = hardware_uid
        if os_version:
            body["os_version"] = os_version
        req = urllib.request.Request(
            f"{base}/api/v1/retina/ingest",
            data=json.dumps(body).encode(),
            method="POST",
            headers={
                "Content-Type": "application/json",
                _DEVICE_SECRET_HEADER: hub_token_secret,
                **({"X-Raven-Agent": key} if key else {}),
            },
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT_SECS) as resp:
            ok = 200 <= resp.status < 300
            if not ok:
                _log.warning("retina ingest HTTP %s for token %s",
                             resp.status, token_id[:8])
            return ok

    try:
        return _do_ingest(hub_token_id)
    except urllib.error.HTTPError as e:
        if e.code == 401:
            # Token expired — attempt renewal then retry once.
            _log.info("retina ingest 401 for token %s — attempting renewal",
                      hub_token_id[:8])
            new_id = renew_device_token(hub_token_id, hub_url=hub_url,
                                        store_token_fn=store_token_fn)
            if new_id:
                try:
                    return _do_ingest(new_id)
                except Exception as retry_exc:
                    _log.warning("retina ingest retry failed after renewal: %s",
                                 retry_exc)
            return False
        if note_error is not None:
            note_error(e)
        _log.warning("retina ingest HTTP error %s for token %s: %s",
                     e.code, hub_token_id[:8], e.reason)
    except Exception as e:
        _log.warning("retina ingest failed for token %s: %s",
                     hub_token_id[:8], e)
    return False


def request_hub_link_by_identity(
    patron_token: str,
    recipient_email: str,
    host_hint: str,
    org: str | None = None,
    hub_url: str | None = None,
    agent_key: str | None = None,
) -> str:
    """POST /api/v1/devices/patron-link-by-identity — ask the Hub to pair this
    agent with its own device token, for agents installed without Raven's
    self-enroll flow carrying our patron_token forward (B-62: retina linking
    had no trigger when PatronAI and Raven are installed independently or out
    of order; this is the self-healing counterpart run from assembler._run_one
    on every cycle until a match succeeds).

    Unlike post_retina_scan, we have no hub_token_id/secret yet — that is
    exactly what we are asking the Hub to find and hand off (server-to-server,
    directly to PatronAI's own /retina/link endpoint) based on identity alone.

    Returns one of: "linked" | "no_match" | "skipped" | "failed" | "error".
    Never raises.
    """
    base = (hub_url or os.environ.get("RAVEN_HUB_URL", "")).rstrip("/")
    key  = agent_key or os.environ.get("RAVEN_AGENT_KEY", "")
    org  = org or os.environ.get("COMPANY_SLUG", "")
    if not base or not key or not org or not recipient_email or not host_hint:
        _log.debug("request_hub_link_by_identity: missing base/key/org/email/host — skipped")
        return "error"

    try:
        body = json.dumps({
            "org":           org,
            "person_email":  recipient_email,
            "host_hint":     host_hint,
            "patron_token":  patron_token,
        }).encode()
        req = urllib.request.Request(
            f"{base}/api/v1/devices/patron-link-by-identity",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", "X-Raven-Agent": key},
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT_SECS) as resp:
            data = json.loads(resp.read().decode())
            result = data.get("status", "error")
            if result == "linked":
                _log.info("hub link-by-identity succeeded for %s (%s)",
                          patron_token[:8], recipient_email)
            return result
    except urllib.error.HTTPError as e:
        _log.debug("hub link-by-identity HTTP %s for %s: %s",
                   e.code, patron_token[:8], e.reason)
    except Exception as e:
        _log.debug("hub link-by-identity failed for %s: %s", patron_token[:8], e)
    return "error"
