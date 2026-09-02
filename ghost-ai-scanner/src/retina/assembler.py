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
#          Agents without a raven_hub_token_id in their meta.json are
#          silently skipped — they have not been linked to the Hub yet.
#
#          The assembler is STATELESS between calls. All state is in S3.
#
# S3 paths used:
#   Read:  config/HOOK_AGENTS/catalog.json          (agent list)
#   Read:  config/HOOK_AGENTS/{token}/meta.json     (hub_token_id, email)
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
from .hub_client  import post_retina_scan

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
        stats = {"agents_checked": 0, "scans_posted": 0,
                 "unchanged": 0, "skipped_no_token": 0, "errors": 0}
        tokens = self._list_agent_tokens()
        for token in tokens:
            stats["agents_checked"] += 1
            try:
                result = self._run_one(token)
                if result == "posted":
                    stats["scans_posted"] += 1
                elif result == "unchanged":
                    stats["unchanged"] += 1
                elif result == "skipped":
                    stats["skipped_no_token"] += 1
                elif result == "error":
                    stats["errors"] += 1
            except Exception as e:
                _log.error("retina cycle error for agent %s: %s", token[:8], e)
                stats["errors"] += 1
        _log.info("retina cycle: %s", stats)
        return stats

    # ── Per-agent logic ───────────────────────────────────────────────────────

    def _run_one(self, patron_token: str) -> str:
        """Process one agent. Returns: 'posted'|'unchanged'|'skipped'|'error'."""
        # Read agent metadata to get the Hub device token.
        meta = self._read_meta(patron_token)
        hub_token_id = (meta.get("raven_hub_token_id") or "").strip()
        if not hub_token_id:
            return "skipped"

        # Read the agent's latest endpoint scan from S3.
        scan = self._read_scan(patron_token)
        if scan is None:
            _log.debug("no scan yet for agent %s", patron_token[:8])
            return "skipped"

        # Extract and normalise dimensions.
        raw_dims   = extract_dimensions(scan)
        norm_dims  = normalise(raw_dims)
        new_hash   = compute_hash(norm_dims)

        # Skip if hash unchanged since last post.
        last_hash  = self._read_last_hash(patron_token)
        if last_hash == new_hash:
            return "unchanged"

        # POST to Hub.
        ok = post_retina_scan(
            hub_token_id=hub_token_id,
            retina_hash=new_hash,
            dimensions=norm_dims,
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
