# =============================================================
# FILE: src/store/agent_store.py
# VERSION: 2.1.0
# UPDATED: 2026-07-21
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: S3-backed catalog for agent delivery packages.
#          Generates tokens, bcrypt-hashes OTPs, uploads packages,
#          mints presigned URLs, tracks install status.
#          All control-plane objects under config/HOOK_AGENTS/.
#          Telemetry from agents lands under ocsf/agent/ so the
#          ingestor walks it on every cycle.
# DEPENDS: boto3, bcrypt
# AUDIT LOG:
#   v1.0.0  2026-04-19  Initial — agent delivery system.
#   v1.1.0  2026-04-19  S3 prefix: agents/ → config/HOOK_AGENTS/.
#   v1.2.0  2026-04-19  heartbeat_put_url (7-day TTL) for liveness pings.
#   v1.3.0  2026-04-20  delete_package — purge all objects under token prefix.
#   v1.4.0  2026-04-20  get_artifact_url for DMG/EXE artifacts.
#   v1.5.0  2026-04-20  scan_put_url — presigned PUT for endpoint scan results.
#   v1.6.0  2026-04-20  authorized_domains persisted; authorized_get_url.
#   v2.0.0  2026-04-25  Step 0 — heartbeat key moved into ocsf/agent/heartbeats/
#                       so ingestor sees it (was clobbering status.json outside
#                       the walked prefix). New write_url_bundle() + urls_refresh_url
#                       so the laptop refreshes presigned URLs daily — the 7-day
#                       cliff that was silently killing fleet agents is gone.
#   v2.1.0  2026-07-21  get_url_bundle() — re-mint + return the urls.json bundle
#                       directly, for the new /agent/url-refresh/{token} API
#                       fallback. RCA (2026-06-10 to 2026-06-19 fleet heartbeat
#                       outage): urls_refresh_url.txt is ITSELF a presigned URL
#                       with the same 7-day TTL, and nothing re-pushes a fresh
#                       one down to the laptop once it expires — every agent
#                       got stuck 403-ing forever with no self-recovery path.
# =============================================================

import json
import logging
import os
import secrets
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

import bcrypt

from .base_store import BaseStore

log = logging.getLogger("marauder-scan.agent_store")

HOOK_AGENTS_PREFIX = "config/HOOK_AGENTS"
CATALOG_KEY        = f"{HOOK_AGENTS_PREFIX}/catalog.json"
# Raw network-capture landing zone, one prefix per device token. The token
# prefix IS the write-isolation boundary: a presigned POST policy scoped to
# it cannot touch another device's objects.
CAPTURE_PREFIX     = "ocsf/tshark"
# Git-diff signals from the pre-commit hook. Previously uploaded with
# `aws s3 cp`, which hardcoded s3:// (so it could never reach MinIO) and
# needed long-lived AWS credentials on an employee laptop. Now a presigned
# POST like everything else - the device holds no credentials at all.
#
# NOT scoped per token, unlike CAPTURE_PREFIX: the existing key layout is
# ocsf/agent/git-diffs/{device_id}-{timestamp}.json, flat across the fleet.
# Narrowing it to a per-token prefix would be the stronger isolation, but it
# changes where these objects live and what already reads them - a separate
# change, deliberately not smuggled in here.
GITDIFF_PREFIX     = "ocsf/agent/git-diffs"
# A diff snippet is capped at 5 KB by the hook itself; 1 MB is generous
# headroom while still bounding what a buggy or compromised device can push.
GITDIFF_MAX_BYTES  = 1024 * 1024
# Upper bound on a single capture batch. An hour of metadata gzips to a few
# hundred KB, so this is generous - it exists so a buggy or compromised
# device cannot upload unbounded objects into the bucket.
CAPTURE_MAX_BYTES  = 50 * 1024 * 1024
PRESIGN_TTL        = 172800   # 48 hours — installer + meta delivery
HEARTBEAT_PRESIGN_TTL = 604800  # 7 days  — max AWS IAM presigned PUT TTL
# Minimum gap between re-mints for the same token via get_url_bundle() (the
# public /agent/url-refresh/{token} fallback) — cheap abuse throttle, not a
# real rate limit. Legitimate heartbeat usage only calls this occasionally.
URL_REFRESH_COOLDOWN_SECS = 60


class AgentStore(BaseStore):
    """Manages OTP-locked agent installer packages on S3."""

    # ── OTP helpers ───────────────────────────────────────────

    def generate_otp(self) -> str:
        """Return a cryptographically secure 6-digit OTP string."""
        return str(secrets.randbelow(900000) + 100000)

    def hash_otp(self, otp: str) -> str:
        """Return bcrypt hash of otp (rounds=12). Store the hash, not the OTP."""
        return bcrypt.hashpw(otp.encode(), bcrypt.gensalt(rounds=12)).decode()

    def check_otp(self, otp: str, hashed: str) -> bool:
        """Validate OTP against stored bcrypt hash."""
        try:
            return bcrypt.checkpw(otp.encode(), hashed.encode())
        except Exception:
            return False

    # ── Object reads ──────────────────────────────────────────

    def get_object_text(self, key: str) -> str:
        """Read an S3 object as UTF-8 text. Used by /agent/provision to
        return the freshly-rendered installer script inline to Raven so
        it can be inlined into the Raven installer via a heredoc.

        Decodes with utf-8-sig, not plain utf-8 (PR#14/#15 review): .ps1
        installer scripts are written with a UTF-8 BOM (Windows PowerShell
        5.1 needs it to not misread em-dashes as the system ANSI codepage —
        see render_agent_package.py v1.6.1). Plain utf-8 doesn't strip a
        BOM on decode, so /agent/provision would return script_content with
        a leading U+FEFF for windows packages. utf-8-sig strips it when
        present and is a no-op when absent (e.g. .sh has no BOM), so this
        is safe for every key this method reads."""
        raw = self._get(key)
        return raw.decode("utf-8-sig") if raw else ""

    # ── Package lifecycle ─────────────────────────────────────

    def create_package(
        self,
        recipient_name: str,
        recipient_email: str,
        os_type: str,
        rendered_script: str,
        otp_hash: str,
        authorized_domains: list | None = None,
    ) -> Optional[str]:
        """
        Upload meta.json + status.json + installer + authorized.csv to S3.
        authorized_domains: per-user list of allowed tool domains/packages.
        Returns token string or None on failure.
        """
        token      = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=48)).isoformat()
        ext        = "ps1" if os_type == "windows" else "sh"
        script_key = f"{HOOK_AGENTS_PREFIX}/{token}/setup_agent.{ext}"
        domains    = authorized_domains or []

        meta = {
            "token":              token,
            "recipient_name":     recipient_name,
            "recipient_email":    recipient_email,
            "os_type":            os_type,
            "otp_hash":           otp_hash,
            "created_at":         created_at,
            "expires_at":         expires_at,
            "script_key":         script_key,
            "authorized_domains": domains,
        }
        status = {"token": token, "status": "pending", "updated_at": created_at}
        # authorized.csv: one domain per line, no header — agent fetches on every scan
        auth_csv = "\n".join(domains)

        try:
            self._put(f"{HOOK_AGENTS_PREFIX}/{token}/meta.json",
                      json.dumps(meta).encode(), "application/json")
            self._put(f"{HOOK_AGENTS_PREFIX}/{token}/status.json",
                      json.dumps(status).encode(), "application/json")
            self._put(f"{HOOK_AGENTS_PREFIX}/{token}/authorized.csv",
                      auth_csv.encode(), "text/csv")
            self._put(script_key,
                      rendered_script.encode(), "text/plain")
            self._catalog_add(token, recipient_name, recipient_email, os_type, created_at)
            return token
        except Exception as e:
            log.error("create_package failed: %s", e)
            return None

    def get_presigned_urls(self, token: str, os_type: str) -> dict:
        """
        Return presigned URLs for client use. Each URL is a time-bound,
        key-locked S3 capability. Heartbeat lands inside ocsf/ so the
        ingestor walks it. urls_refresh_url points at a daily-rotated
        bundle so the agent can pull fresh URLs before the 7-day cliff.
        """
        ext = "ps1" if os_type == "windows" else "sh"
        try:
            return {
                "installer_url":       self._sign_get(f"{HOOK_AGENTS_PREFIX}/{token}/setup_agent.{ext}", PRESIGN_TTL),
                "meta_url":            self._sign_get(f"{HOOK_AGENTS_PREFIX}/{token}/meta.json",           PRESIGN_TTL),
                "status_put_url":      self._sign_put(f"{HOOK_AGENTS_PREFIX}/{token}/status.json",         PRESIGN_TTL),
                "heartbeat_put_url":   self._sign_put(f"ocsf/agent/heartbeats/{token}/latest.json",        HEARTBEAT_PRESIGN_TTL),
                "scan_put_url":        self._sign_put(f"ocsf/agent/scans/{token}/latest.json",             HEARTBEAT_PRESIGN_TTL),
                "authorized_get_url":  self._sign_get(f"{HOOK_AGENTS_PREFIX}/{token}/authorized.csv",      HEARTBEAT_PRESIGN_TTL),
                "urls_refresh_url":    self._sign_get(f"{HOOK_AGENTS_PREFIX}/{token}/urls.json",           HEARTBEAT_PRESIGN_TTL),
                # Capture companion. A presigned PUT binds one URL to exactly
                # one key, which is why scans overwrite latest.json - fine for
                # a snapshot, useless for a stream of hourly batches. POST with
                # a prefix policy is the mechanism that lifts that.
                "capture_post":        self._sign_post(f"{CAPTURE_PREFIX}/{token}/", HEARTBEAT_PRESIGN_TTL),
                "code_manifest_url":   self._sign_get(f"{HOOK_AGENTS_PREFIX}/{token}/code_manifest.json", HEARTBEAT_PRESIGN_TTL),
                # Scan agent's git-diff hook. JSON, not gzip - the hook posts
                # a plain JSON document.
                "gitdiff_post":        self._sign_post(f"{GITDIFF_PREFIX}/", HEARTBEAT_PRESIGN_TTL,
                                                       max_bytes=GITDIFF_MAX_BYTES,
                                                       content_prefix="application/json"),
            }
        except Exception as e:
            log.error("get_presigned_urls failed [%s]: %s", token, e)
            return {}

    def _sign_get(self, key: str, ttl: int) -> str:
        """Mint a presigned GET URL. Caller catches errors."""
        return self.s3.generate_presigned_url(
            "get_object", Params={"Bucket": self.bucket, "Key": key}, ExpiresIn=ttl,
        )

    def _sign_put(self, key: str, ttl: int) -> str:
        """Mint a presigned PUT URL with JSON content-type binding."""
        return self.s3.generate_presigned_url(
            "put_object",
            Params={"Bucket": self.bucket, "Key": key, "ContentType": "application/json"},
            ExpiresIn=ttl,
        )

    def _sign_post(self, prefix: str, ttl: int,
                   max_bytes: int = CAPTURE_MAX_BYTES,
                   content_prefix: str = "application/") -> dict:
        """Mint a presigned POST policy authorising MANY keys under `prefix`.

        Returns boto3's {"url": ..., "fields": {...}} verbatim; the client
        overrides "key" per upload and appends the file part LAST (S3 ignores
        form fields that appear after the file).

        Why POST rather than PUT: a presigned PUT is bound to one exact key,
        so it can only ever overwrite. Capture produces a stream of hourly
        batches with rotating names, which a PUT cannot express without a
        server round-trip per file.

        Two conditions beyond the prefix, both deliberate:
          * content-length-range - bounds what a buggy or compromised device
            can push into the bucket.
          * Content-Type starts-with "application/" - the companion uploads
            gzip; this stops the same policy being reused to plant HTML that
            would be served back from the bucket origin.
        """
        return self.s3.generate_presigned_post(
            Bucket=self.bucket,
            Key=prefix + "${filename}",
            Conditions=[
                ["starts-with", "$key", prefix],
                ["content-length-range", 1, max_bytes],
                ["starts-with", "$Content-Type", content_prefix],
            ],
            ExpiresIn=ttl,
        )

    def write_code_manifest(self, token: str, manifest: dict) -> bool:
        """Publish {filename: sha256} for the capture companion's code.

        The companion verifies its own files against this at every startup and
        refuses to run on a mismatch. It is served from the object store rather
        than shipped to disk on purpose: whoever can modify a .py on the device
        can equally modify a manifest sitting next to it, so a local copy would
        prove nothing.

        This is integrity assurance, NOT tamper-proofing - a local administrator
        can also redirect the fetch. It detects accidental and casual
        modification, which is what it is for.
        """
        try:
            self._put(f"{HOOK_AGENTS_PREFIX}/{token}/code_manifest.json",
                      json.dumps(manifest, indent=2, sort_keys=True).encode(),
                      "application/json")
            return True
        except Exception as e:
            log.error("write_code_manifest [%s] failed: %s", token, e)
            return False

    def write_url_bundle(self, token: str, os_type: str) -> bool:
        """Re-mint heartbeat / scan / authorized URLs and write the bundle to S3.

        Called by the daily url_refresh_loop. The bundle excludes urls_refresh_url
        itself (the agent already has that one and we don't want a chicken-and-egg).
        """
        urls = self.get_presigned_urls(token, os_type)
        if not urls:
            return False
        bundle = {
            "minted_at":          datetime.now(timezone.utc).isoformat(),
            "expires_at":         (datetime.now(timezone.utc) + timedelta(seconds=HEARTBEAT_PRESIGN_TTL)).isoformat(),
            "heartbeat_put_url":  urls["heartbeat_put_url"],
            "scan_put_url":       urls["scan_put_url"],
            "authorized_get_url": urls["authorized_get_url"],
            # Capture companion. Re-minted on the same 24h cadence as
            # everything else - no second refresh mechanism, and the 7-day
            # TTL cliff applies to these exactly as it does to the rest.
            "capture_post":       urls.get("capture_post", {}),
            "code_manifest_url":  urls.get("code_manifest_url", ""),
            # Scan agent's git-diff hook - re-minted on the same 24h cadence
            # as everything else, so it expires and renews like the rest.
            "gitdiff_post":       urls.get("gitdiff_post", {}),
        }
        try:
            self._put(f"{HOOK_AGENTS_PREFIX}/{token}/urls.json",
                      json.dumps(bundle).encode(), "application/json")
            return True
        except Exception as e:
            log.error("write_url_bundle [%s] failed: %s", token, e)
            return False

    def get_url_bundle(self, token: str, os_type: str = "windows") -> Optional[dict]:
        """Return this agent's urls.json bundle, re-minting it first unless
        one was already minted within URL_REFRESH_COOLDOWN_SECS.

        Backs the /agent/url-refresh/{token} API fallback (RCA: the agent's
        own urls_refresh_url.txt is a presigned GET with the same 7-day TTL
        as everything else, and nothing re-pushes a fresh one to the laptop
        once it expires).

        ACCEPTED TRADE-OFF (PR#10 review): the token here is checked only
        for existence against meta.json — unlike a presigned URL, it isn't
        cryptographically bound to an expiry, so a leaked token grants
        indefinite re-mint access for as long as the agent stays installed.
        That's inherent to the feature (agents must self-heal forever, not
        just within meta.json's 48h install window). The cooldown below is
        a cheap throttle against automated abuse, not a real rate limit —
        every call is logged (truncated token) so abuse is at least
        detectable. Returns None for an unknown token or on any failure.
        os_type only affects installer_url/meta_url, neither of which this
        bundle includes, so it's safe to default."""
        short = token[:8]
        if not self._get(f"{HOOK_AGENTS_PREFIX}/{token}/meta.json"):
            log.info("get_url_bundle [%s...]: unknown token", short)
            return None

        existing_raw = self._get(f"{HOOK_AGENTS_PREFIX}/{token}/urls.json")
        if existing_raw:
            try:
                existing = json.loads(existing_raw)
                minted_at = datetime.fromisoformat(existing["minted_at"])
                age = (datetime.now(timezone.utc) - minted_at).total_seconds()
                if age < URL_REFRESH_COOLDOWN_SECS:
                    log.info("get_url_bundle [%s...]: cooldown hit (age=%.0fs), serving cached bundle", short, age)
                    return existing
            except Exception:
                pass   # cached bundle unreadable — fall through and re-mint

        if not self.write_url_bundle(token, os_type):
            log.info("get_url_bundle [%s...]: re-mint failed", short)
            return None
        log.info("get_url_bundle [%s...]: re-minted", short)
        raw = self._get(f"{HOOK_AGENTS_PREFIX}/{token}/urls.json")
        try:
            return json.loads(raw) if raw else None
        except Exception as e:
            log.error("get_url_bundle [%s...] failed to parse bundle: %s", short, e)
            return None

    def get_artifact_url(self, key: str) -> str:
        """Return a presigned GET URL for an arbitrary S3 key (48 h TTL)."""
        try:
            return self.s3.generate_presigned_url(
                "get_object",
                Params={"Bucket": self.bucket, "Key": key},
                ExpiresIn=PRESIGN_TTL,
            )
        except Exception as e:
            log.error("get_artifact_url failed [%s]: %s", key, e)
            return ""

    def get_heartbeat(self, token: str) -> Optional[dict]:
        """Read the latest heartbeat JSON for an agent token.
        Returns None if the key does not exist or cannot be parsed."""
        raw = self._get(f"ocsf/agent/heartbeats/{token}/latest.json")
        if not raw:
            return None
        try:
            return json.loads(raw)
        except Exception as e:
            log.debug("Heartbeat parse failed [%s...]: %s", token[:8], e)
            return None

    def get_authorized_domains(self, token: str) -> list:
        """Read current authorized_domains for a token from meta.json."""
        try:
            raw = self._get(f"{HOOK_AGENTS_PREFIX}/{token}/meta.json")
            if not raw:
                return []
            return json.loads(raw).get("authorized_domains", [])
        except Exception as e:
            log.error("get_authorized_domains failed [%s]: %s", token, e)
            return []

    def update_authorized_domains(self, token: str, domains: list) -> bool:
        """
        Update authorized domains for an existing agent package.
        Writes new authorized.csv to S3 (agent picks it up within 30 min).
        Also updates meta.json so the UI reflects the current state.
        """
        domains = [d.strip().lower() for d in domains if d.strip()]
        try:
            # Update authorized.csv — agent fetches this on every scan
            auth_csv = "\n".join(domains)
            self._put(f"{HOOK_AGENTS_PREFIX}/{token}/authorized.csv",
                      auth_csv.encode(), "text/csv")
            # Patch meta.json
            raw = self._get(f"{HOOK_AGENTS_PREFIX}/{token}/meta.json")
            if raw:
                meta = json.loads(raw)
                meta["authorized_domains"] = domains
                meta["authorized_updated_at"] = datetime.now(timezone.utc).isoformat()
                self._put(f"{HOOK_AGENTS_PREFIX}/{token}/meta.json",
                          json.dumps(meta).encode(), "application/json")
            log.info("updated authorized_domains [%s]: %s", token[:8], domains)
            return True
        except Exception as e:
            log.error("update_authorized_domains failed [%s]: %s", token, e)
            return False

    def list_catalog(self) -> list:
        """Return all catalog entries as a list of dicts."""
        try:
            raw = self._get(CATALOG_KEY)
            if not raw:
                return []
            return json.loads(raw)
        except Exception as e:
            log.error("list_catalog failed: %s", e)
            return []

    def refresh_statuses(self, catalog: list) -> list:
        """Hydrate each catalog entry with current status from S3."""
        for entry in catalog:
            try:
                raw = self._get(f"{HOOK_AGENTS_PREFIX}/{entry['token']}/status.json")
                if raw:
                    entry["status"] = json.loads(raw).get("status", "pending")
            except Exception:
                pass
        return catalog

    # ── Catalog management ────────────────────────────────────

    def _catalog_add(
        self,
        token: str,
        recipient_name: str,
        recipient_email: str,
        os_type: str,
        created_at: str,
    ) -> None:
        """Append a new entry to catalog.json on S3."""
        catalog = self.list_catalog()
        catalog.append({
            "token":           token,
            "recipient_name":  recipient_name,
            "recipient_email": recipient_email,
            "os_type":         os_type,
            "created_at":      created_at,
            "status":          "pending",
        })
        try:
            self._put(CATALOG_KEY, json.dumps(catalog, indent=2).encode(), "application/json")
        except Exception as e:
            log.error("_catalog_add write failed: %s", e)

    def delete_package(self, token: str, os_type: str = "") -> bool:
        """
        Remove package from catalog and purge ALL S3 objects under the token prefix.
        Covers sh, ps1, dmg, exe, meta.json, status.json — no hard-coded list needed.
        os_type retained for API compatibility but no longer drives key selection.
        """
        prefix = f"{HOOK_AGENTS_PREFIX}/{token}/"
        try:
            paginator = self.s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
                objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
                if objects:
                    self.s3.delete_objects(
                        Bucket=self.bucket,
                        Delete={"Objects": objects, "Quiet": True},
                    )
            catalog = [e for e in self.list_catalog() if e["token"] != token]
            self._put(CATALOG_KEY, json.dumps(catalog, indent=2).encode(),
                      "application/json")
            log.info("delete_package: purged prefix %s (%d objects)", prefix, len(objects) if 'objects' in dir() else 0)
            return True
        except Exception as e:
            log.error("delete_package failed [%s]: %s", token, e)
            return False
