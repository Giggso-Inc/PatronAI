# =============================================================
# FILE: scripts/build_agent_update_bundle.py
# VERSION: 1.0.0
# OWNER: Giggso Inc
# PURPOSE: Package the generic, per-device agent scripts (heartbeat/scan/
#          hook_chain/pre_commit_hook/diagnose) into a versioned zip for
#          apply_update.ps1/.sh to fetch and install, then publish the org's
#          self-update settings blob (config/HOOK_AGENTS/_updates/settings.json)
#          pointing at it.
#
#          Unlike render_agent_package.py, this does NOT take a recipient or
#          OTP - it ships the SAME generic script bodies every device already
#          gets at install time (they bake in no per-recipient secrets; only
#          config.json/the *_url files do, and apply_update.* never touches
#          those). Run this once per agent-protocol release, after bumping
#          agent/AGENT_VERSION.
#
#          Callable from Streamlit (the "Publish current agent scripts as
#          latest version" button on the Deploy Agents tab) or the CLI.
# =============================================================
from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Optional

log = logging.getLogger("marauder-scan.build_agent_update_bundle")

TEMPLATE_DIR = Path(__file__).parent.parent / "agent" / "install"
AGENT_VERSION_FILE = Path(__file__).parent.parent / "agent" / "AGENT_VERSION"

# Matches apply_update.ps1's $UpdatableFiles / apply_update.sh's
# $UPDATABLE_FILES - keep these three lists in sync. agent_version.txt is
# NOT included here: apply_update.* writes it itself once the rest of the
# bundle is verified in place, it is never shipped IN the bundle.
WINDOWS_FILES = ["heartbeat.ps1", "scan.ps1", "hook_chain.ps1", "pre_commit_hook.ps1", "diagnose.ps1"]
UNIX_FILES    = ["heartbeat.sh",  "scan.sh",  "hook_chain.sh",  "pre_commit_hook.sh",  "diagnose.sh"]


def _build_zip(filenames: list[str]) -> bytes:
    """Zip the named files straight from agent/install/ - flat, no directory
    prefix, matching what apply_update.* extracts into a temp dir and copies
    file-by-file (never a directory swap - see apply_update.*'s own header
    comment on why config.json/identity files must never be touched)."""
    missing = [f for f in filenames if not (TEMPLATE_DIR / f).exists()]
    if missing:
        raise FileNotFoundError(f"Cannot build update bundle - missing source file(s): {missing}")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in filenames:
            zf.write(TEMPLATE_DIR / name, arcname=name)
    return buf.getvalue()


def _register_with_superadmin_catalog(product: str, platform: str, version: str,
                                       checksum: str, storage_location: str) -> None:
    """Best-effort registration with raven-enterprise-admin's Installer
    catalog (POST /api/super-admin/installers/upload) - never raises, never
    fails the calling publish. Unlike Cowork/Raven (which upload to S3 by
    hand and register as a deliberate second step), this bundle's own upload
    already happened inside build_and_publish() via store._put() - so this
    call happens automatically right after, rather than needing a human to
    run a separate script once they know where the file ended up.

    Silently a no-op when SUPERADMIN_URL/SUPERADMIN_JWT aren't set - most
    environments won't have them configured, and a missing/unreachable
    super admin must never turn a successful agent-version publish into a
    reported failure.
    """
    base_url = os.environ.get("SUPERADMIN_URL", "").rstrip("/")
    jwt = os.environ.get("SUPERADMIN_JWT", "")
    if not base_url or not jwt:
        return

    body = {
        "product": product, "platform": platform, "version": version,
        "checksum": checksum, "storageLocation": storage_location,
    }
    req = urllib.request.Request(
        f"{base_url}/api/super-admin/installers/upload",
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={"Authorization": f"Bearer {jwt}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15):
            log.info("registered %s %s v%s with the super-admin catalog", product, platform, version)
    except (urllib.error.HTTPError, urllib.error.URLError) as e:
        log.warning("super-admin catalog registration failed (non-fatal) for %s %s v%s: %s",
                    product, platform, version, e)


def build_and_publish(store, agent_version: Optional[str] = None) -> dict:
    """Build both platform bundles, upload them, and write the org's
    self-update settings blob (store.set_update_settings). Does NOT flip
    auto_update_enabled - that stays whatever an admin last set it to, so
    publishing a build never silently turns auto-update on for an org that
    had it off.

    Returns {"success": bool, "version": str, "error": str|None}.
    """
    version = agent_version or (
        AGENT_VERSION_FILE.read_text(encoding="utf-8").strip()
        if AGENT_VERSION_FILE.exists() else ""
    )
    if not version:
        return {"success": False, "error": "agent/AGENT_VERSION is empty or missing"}

    try:
        windows_zip = _build_zip(WINDOWS_FILES)
        unix_zip    = _build_zip(UNIX_FILES)
    except FileNotFoundError as e:
        return {"success": False, "error": str(e)}

    windows_sha = hashlib.sha256(windows_zip).hexdigest()
    unix_sha    = hashlib.sha256(unix_zip).hexdigest()

    windows_key = f"config/HOOK_AGENTS/_updates/{version}/bundle-windows.zip"
    unix_key    = f"config/HOOK_AGENTS/_updates/{version}/bundle-unix.zip"

    try:
        if not store._put(windows_key, windows_zip, "application/zip"):
            return {"success": False, "error": f"Upload failed: {windows_key}"}
        if not store._put(unix_key, unix_zip, "application/zip"):
            return {"success": False, "error": f"Upload failed: {unix_key}"}
    except Exception as e:
        log.error("build_and_publish: upload failed: %s", e)
        return {"success": False, "error": str(e)}

    settings = store.get_update_settings()
    settings["latest_agent_version"]   = version
    settings["bundle_key_windows"]     = windows_key
    settings["bundle_key_unix"]        = unix_key
    settings["bundle_sha256_windows"]  = windows_sha
    settings["bundle_sha256_unix"]     = unix_sha

    if not store.set_update_settings(settings):
        return {"success": False, "error": "Failed to write update settings"}

    # Best-effort, never affects the {"success": True, ...} already earned by
    # the two store._put() calls above - see _register_with_superadmin_catalog's
    # own docstring for why a missing/unreachable super admin is a no-op here.
    _register_with_superadmin_catalog("patronai", "windows", version, windows_sha,
                                       f"s3://{store.bucket}/{windows_key}")
    _register_with_superadmin_catalog("patronai", "unix", version, unix_sha,
                                       f"s3://{store.bucket}/{unix_key}")

    log.info("build_and_publish: published agent version %s "
              "(windows sha256=%s..., unix sha256=%s...)",
              version, windows_sha[:12], unix_sha[:12])
    return {"success": True, "version": version, "error": None}


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from src.store.agent_store import AgentStore

    store = AgentStore(bucket="")  # picks up MARAUDER_SCAN_BUCKET/OBJECT_BUCKET from env
    result = build_and_publish(store)
    if result["success"]:
        print(f"Published agent version {result['version']}")
    else:
        print(f"FAILED: {result['error']}", file=sys.stderr)
        sys.exit(1)
