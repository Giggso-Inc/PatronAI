# =============================================================
# FILE: src/normalizer/identity_catalog.py
# VERSION: 1.0.0
# PURPOSE: Resolve a device TOKEN to the enrolled user's email.
#
# The agent ships a device token, never a username - it has no idea who is
# using the machine. config/HOOK_AGENTS/catalog.json is the only place that
# binds the two, because create_package records recipient_email at invite
# time (agent_store.py). jobs/tshark_ingest.catalog_identity() already does
# this for capture data; the endpoint-scan and heartbeat paths did not, so
# every scan finding landed with owner=<hostname> and email="".
#
# owner must be the EMAIL: it is the join key used by identity_resolver and
# dashboard/ui/policy_context_loader.sync_scanned_users_from_events, so a
# hostname there also breaks downstream user sync.
#
# Cached: the normalizer runs per event (hundreds per scan) while the
# catalog is a single object for the whole fleet.
# =============================================================
import json
import logging
import os
import time
from typing import Optional

log = logging.getLogger("marauder-scan.normalizer.identity_catalog")

CATALOG_KEY = "config/HOOK_AGENTS/catalog.json"
_TTL = int(os.environ.get("IDENTITY_CATALOG_TTL_S", "300"))

_cache: dict = {}
_cache_at: float = 0.0


def _load() -> dict:
    """token -> recipient_email. Returns {} on any failure (fail-open)."""
    global _cache, _cache_at
    now = time.time()
    if _cache and (now - _cache_at) < _TTL:
        return _cache
    try:
        from store.object_store import get_object_store, default_bucket
        store = get_object_store()
        raw = store.get(default_bucket(), CATALOG_KEY)
        entries = json.loads(raw.decode("utf-8"))
        table = {}
        for e in entries if isinstance(entries, list) else []:
            if not isinstance(e, dict):
                continue
            tok   = (e.get("token") or "").strip()
            email = (e.get("recipient_email") or "").strip()
            if tok and email:
                table[tok] = email
        _cache, _cache_at = table, now
        log.debug("identity catalog loaded: %d tokens", len(table))
    except Exception as exc:
        # Fail open - a missing catalog must not drop findings, it only
        # means they fall back to the hostname as before.
        log.warning("identity catalog unavailable, falling back to hostname: %s", exc)
        _cache_at = now
    return _cache


def email_for_token(token: str) -> Optional[str]:
    """Enrolled user's email for a device token, or None."""
    if not token:
        return None
    return _load().get(token.strip()) or None
