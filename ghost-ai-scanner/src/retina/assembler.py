# =============================================================
# FILE: src/retina/assembler.py
# VERSION: 1.0.0
# UPDATED: 2026-09-02
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: Orchestrates the full retina fingerprint cycle for every
#          active Patron agent.
#
#          Per agent, on each invocation:
#            1. Read latest scan from S3 (ocsf/agent/scans/{token}/latest.json)
#            2. Extract D1-D7 dimensions using collector
#            3. Normalise and compute SHA-256 hash using normaliser
#            4. Compare against the last posted hash (cached in S3)
#            5. POST to Hub only if the hash changed or it is the
#               first scan for this agent
#
#          Agents without complete Hub token credentials in meta.json fire
#          a best-effort identity-based self-heal link attempt (B-62) and
#          are skipped for this cycle either way — they are not yet linked
#          to the Hub, whether or not this cycle's attempt succeeds.
#
#          The assembler is STATELESS between calls. All state is in S3.
#
# S3 paths used:
#   Read:  config/HOOK_AGENTS/catalog.json          (agent list)
#   Read:  config/HOOK_AGENTS/{token}/meta.json     (hub token credentials, email)
#   Read:  config/HOOK_AGENTS/{token}/status.json   (reported hostname, B-62)
#   Read:  ocsf/agent/scans/{token}/latest.json     (raw scan from agent)
#   Read:  ocsf/agent/retina/{token}/last.json      (last posted hash)
#   Write: ocsf/agent/retina/{token}/last.json      (update after post)
#
# DEPENDS: json, logging (stdlib); retina.collector, normaliser, hub_client
# AUDIT LOG:
#   v1.0.0  2026-09-02  Initial. RavenHub Card — Patron side.
# =============================================================

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from .collector   import extract_dimensions
from .normaliser  import normalise, compute_hash
from .hub_client  import post_retina_scan, request_hub_link_by_identity
from .device_info import get_device_info

if TYPE_CHECKING:
    from store.base_store import BaseStore

_log = logging.getLogger("marauder-scan.retina.assembler")

_SCAN_PREFIX   = "ocsf/agent/scans"
_RETINA_PREFIX = "ocsf/agent/retina"
_AGENTS_PREFIX = "config/HOOK_AGENTS"


class RetinaAssembler:
    """Runs the retina fingerprint cycle for every linked Patron agent."""

    def __init__(self, store: "BaseStore") -> None:
        self._store = store

    # ── Public entry point ────────────────────────────────────────────────────

    def run_all(self) -> dict:
        """Run the retina cycle for all active agents. Returns summary stats."""
        stats = {"agents_checked": 0, "scans_posted": 0, "unchanged": 0,
                  "skipped_no_token": 0, "skipped_no_scan": 0, "errors": 0}
        tokens = self._list_agent_tokens()
        for token in tokens:
            stats["agents_checked"] += 1
            try:
                result = self._run_one(token)
                if result == "posted":
                    stats["scans_posted"] += 1
                elif result == "unchanged":
                    stats["unchanged"] += 1
                elif result == "skipped_no_token":
                    stats["skipped_no_token"] += 1
                elif result == "skipped_no_scan":
                    stats["skipped_no_scan"] += 1
                elif result == "error":
                    stats["errors"] += 1
            except Exception as e:
                _log.error("retina cycle error for agent %s: %s", token[:8], e)
                stats["errors"] += 1
        _log.info("retina cycle: %s", stats)
        return stats

    # ── Per-agent logic ───────────────────────────────────────────────────────

    def _run_one(self, patron_token: str) -> str:
        """Process one agent. Returns:
        'posted'|'unchanged'|'skipped_no_token'|'skipped_no_scan'|'error'.
        The two skip reasons are kept distinct (B-62) so operators can tell
        "never linked to the Hub yet" (self-heal is attempted) apart from
        "linked, just hasn't scanned yet" (nothing to attempt)."""
        # Read agent metadata to get the Hub device token.
        meta = self._read_meta(patron_token)
        hub_token_id = (meta.get("raven_hub_token_id") or "").strip()
        hub_token_secret = (meta.get("raven_hub_token_secret") or "").strip()
        if not hub_token_id or not hub_token_secret:
            self._try_link_by_identity(patron_token, meta)
            return "skipped_no_token"

        # Read the agent's latest endpoint scan from S3.
        scan = self._read_scan(patron_token)
        if scan is None:
            _log.debug("no scan yet for agent %s", patron_token[:8])
            return "skipped_no_scan"

        # Extract and normalise dimensions.
        raw_dims   = extract_dimensions(scan)
        norm_dims  = normalise(raw_dims)
        new_hash   = compute_hash(norm_dims)

        # Skip if hash unchanged since last post.
        last_hash  = self._read_last_hash(patron_token)
        if last_hash == new_hash:
            return "unchanged"

        # POST to Hub — include device metadata so the estate UI can show
        # Device name / OS / hardware UID without a separate lookup.
        dev = get_device_info()
        ok = post_retina_scan(
            hub_token_id=hub_token_id,
            hub_token_secret=hub_token_secret,
            retina_hash=new_hash,
            dimensions=norm_dims,
            device_name=dev.get("device_name") or None,
            hardware_uid=dev.get("hardware_uid") or None,
            os_version=dev.get("os_version") or None,
        )
        if ok:
            # Only persist the new hash when the Hub POST succeeded AND the
            # S3 write succeeded. If _write_last_hash fails silently, we
            # return "error" so the next cycle re-POSTs rather than skipping.
            written = self._write_last_hash(patron_token, new_hash)
            if written:
                _log.info("retina posted for agent %s hash %s",
                          patron_token[:8], new_hash[:12])
                return "posted"
            _log.warning("retina posted to Hub but hash persist failed for %s",
                         patron_token[:8])
        return "error"

    # ── S3 helpers ────────────────────────────────────────────────────────────

    def _list_agent_tokens(self) -> list[str]:
        """Return list of Patron token strings from the agent catalog."""
        try:
            raw = self._store._get(f"{_AGENTS_PREFIX}/catalog.json")
            if not raw:
                return []
            catalog = json.loads(raw)
            # Catalog is a list of {token: ..., status: ...} dicts or plain strings.
            tokens: list[str] = []
            for entry in (catalog if isinstance(catalog, list) else []):
                if isinstance(entry, str):
                    tokens.append(entry)
                elif isinstance(entry, dict):
                    t = entry.get("token", "")
                    if t and entry.get("status", "active") != "revoked":
                        tokens.append(t)
            return tokens
        except Exception as e:
            _log.warning("could not load agent catalog: %s", e)
            return []

    def _read_meta(self, token: str) -> dict:
        try:
            raw = self._store._get(f"{_AGENTS_PREFIX}/{token}/meta.json")
            return json.loads(raw) if raw else {}
        except Exception:
            return {}

    def _read_status(self, token: str) -> dict:
        try:
            raw = self._store._get(f"{_AGENTS_PREFIX}/{token}/status.json")
            return json.loads(raw) if raw else {}
        except Exception:
            return {}

    # ── Hub link self-heal (B-62) ──────────────────────────────────────────────────────────

    def _try_link_by_identity(self, patron_token: str, meta: dict) -> None:
        """Best-effort self-heal: when this agent has never been linked to a
        Hub device token (no raven_hub_token_id in meta.json), ask the Hub to
        find and complete the link using identity alone (recipient_email +
        hostname), rather than waiting on Raven's self-enroll to have carried
        our patron_token forward at install time -- which only happens when
        PatronAI installs BEFORE Raven on the same machine. Neither installer
        script is changed by this: the Hub does the matching and, on success,
        POSTs to our own /retina/link endpoint exactly as /patron-link already
        does today, so this call writes no local state itself -- the next
        cycle simply finds the secret meta.json now has and proceeds normally.
        Cheap and safe to retry every cycle until a match is found.
        """
        recipient_email = (meta.get("recipient_email") or "").strip()
        if not recipient_email:
            return
        status = self._read_status(patron_token)
        host_hint = (status.get("device_id") or "").strip()
        if not host_hint:
            return
        # request_hub_link_by_identity never raises (see its own docstring) --
        # no try/except needed here; it degrades to "error" internally.
        result = request_hub_link_by_identity(
            patron_token=patron_token,
            recipient_email=recipient_email,
            host_hint=host_hint,
        )
        if result == "linked":
            _log.info("retina: hub link-by-identity completed for agent %s",
                      patron_token[:8])

    def _read_scan(self, token: str) -> dict | None:
        try:
            raw = self._store._get(f"{_SCAN_PREFIX}/{token}/latest.json")
            return json.loads(raw) if raw else None
        except Exception as e:
            _log.debug("scan read failed for %s: %s", token[:8], e)
            return None

    def _read_last_hash(self, token: str) -> str:
        try:
            raw = self._store._get(f"{_RETINA_PREFIX}/{token}/last.json")
            if raw:
                return json.loads(raw).get("retina_hash", "")
        except Exception:
            pass
        return ""

    def _write_last_hash(self, token: str, retina_hash: str) -> bool:
        """Write the last posted hash to S3. Returns True on success."""
        try:
            payload = json.dumps({"retina_hash": retina_hash}).encode()
            self._store._put(
                f"{_RETINA_PREFIX}/{token}/last.json",
                payload,
                "application/json",
            )
            return True
        except Exception as e:
            _log.warning("could not persist last hash for %s: %s", token[:8], e)
            return False
