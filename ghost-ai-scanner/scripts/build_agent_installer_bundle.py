# =============================================================
# FILE: scripts/build_agent_installer_bundle.py
# VERSION: 1.0.0
# OWNER: Giggso Inc
# PURPOSE: Package the FULL Patron agent installer (every file under
#          agent/install/ - setup templates, fragments, and the extracted
#          per-device scripts) into a single versioned, common artifact,
#          upload it, and register it with the super-admin Installer
#          catalog. This is Patron's counterpart to CoworkDLP's
#          coworkdlp_v<version>.zip: one common, catalog-tracked artifact
#          per agent-protocol release, instead of a bespoke script
#          re-rendered per recipient.
#
#          Distinct from build_agent_update_bundle.py, which ships only the
#          5 files apply_update.* patches into an EXISTING install. This
#          script ships everything needed for a FRESH install (what
#          render_agent_package.py's OTP/DMG/EXE flow still personalizes
#          and delivers per recipient - this bundle does not replace that
#          delivery path, it gives the underlying installer payload a
#          real version + checksum + catalog row, the way Cowork and Raven
#          already have for their own installers).
#
#          Run this once per agent-protocol release, after bumping
#          agent/AGENT_VERSION - same trigger as build_agent_update_bundle.py.
#          Callable from Streamlit (Deploy Agents tab) or the CLI.
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

log = logging.getLogger("marauder-scan.build_agent_installer_bundle")

TEMPLATE_DIR = Path(__file__).parent.parent / "agent" / "install"
AGENT_VERSION_FILE = Path(__file__).parent.parent / "agent" / "AGENT_VERSION"

# Files that make sense to ship on EVERY platform's installer bundle even
# though their extension is OS-specific elsewhere (fragments are plain
# Python text, concatenated at install/build time - shipping the source
# fragments themselves keeps the bundle self-contained and auditable).
_COMMON_SUFFIXES = (".frag",)


def _all_install_files() -> list[str]:
    """Every top-level file under agent/install/, sorted - mirrors
    generatezip.py's Cowork allowlist ("every top-level script included
    automatically, no manual edit needed when a new file is added")."""
    if not TEMPLATE_DIR.exists():
        return []
    return sorted(p.name for p in TEMPLATE_DIR.iterdir() if p.is_file())


def _build_zip(filenames: list[str]) -> bytes:
    missing = [f for f in filenames if not (TEMPLATE_DIR / f).exists()]
    if missing:
        raise FileNotFoundError(f"Cannot build installer bundle - missing source file(s): {missing}")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in filenames:
            zf.write(TEMPLATE_DIR / name, arcname=name)
        version = (
            AGENT_VERSION_FILE.read_text(encoding="utf-8").strip()
            if AGENT_VERSION_FILE.exists() else "0.0.0"
        )
        zf.writestr("AGENT_VERSION", version)
    return buf.getvalue()


def _register_with_superadmin_catalog(product: str, platform: str, version: str,
                                       checksum: str, storage_location: str) -> None:
    """Best-effort registration with raven-enterprise-admin's Installer
    catalog (POST /api/super-admin/installers/upload). Never raises, never
    fails the calling publish - see build_agent_update_bundle.py's copy of
    this same helper for the full rationale. Kept duplicated rather than
    imported so this script stays runnable standalone, same as its sibling.

    platform="setup" here matches the label Raven's tools/register_installer.py
    and Cowork's register_installer.py already use for their own full-install
    artifact, so a catalog listing can be filtered by platform="setup" across
    all three products consistently - the catalog schema has no separate
    "artifact kind" field, so this string carries that distinction instead.
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
    """Build the one common installer bundle, upload it, and register it
    with the super-admin catalog. Does not touch store.set_update_settings -
    that stays owned by build_agent_update_bundle.py's in-place update path.

    Returns {"success": bool, "version": str, "key": str|None, "sha256": str|None, "error": str|None}.
    """
    version = agent_version or (
        AGENT_VERSION_FILE.read_text(encoding="utf-8").strip()
        if AGENT_VERSION_FILE.exists() else ""
    )
    if not version:
        return {"success": False, "error": "agent/AGENT_VERSION is empty or missing"}

    files = _all_install_files()
    if not files:
        return {"success": False, "error": f"No files found under {TEMPLATE_DIR}"}

    try:
        bundle_zip = _build_zip(files)
    except FileNotFoundError as e:
        return {"success": False, "error": str(e)}

    sha256 = hashlib.sha256(bundle_zip).hexdigest()
    key = f"config/HOOK_AGENTS/_installer/patronai_agent_installer_v{version}.zip"

    try:
        if not store._put(key, bundle_zip, "application/zip"):
            return {"success": False, "error": f"Upload failed: {key}"}
    except Exception as e:
        log.error("build_and_publish: upload failed: %s", e)
        return {"success": False, "error": str(e)}

    # Single cross-platform artifact (setup_agent.ps1.template + .sh.template
    # both ship in the one zip, same as Cowork's setup bundling all three OS
    # scripts) - one catalog row, not two.
    _register_with_superadmin_catalog("patronai", "setup", version, sha256, f"s3://{store.bucket}/{key}")

    log.info("build_and_publish: published installer bundle v%s (%d files, sha256=%s...)",
              version, len(files), sha256[:12])
    return {"success": True, "version": version, "key": key, "sha256": sha256, "error": None}


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from src.store.agent_store import AgentStore

    store = AgentStore(bucket="")  # picks up MARAUDER_SCAN_BUCKET/OBJECT_BUCKET from env
    result = build_and_publish(store)
    if result["success"]:
        print(f"Published installer bundle v{result['version']} -> {result['key']} (sha256={result['sha256'][:12]}...)")
    else:
        print(f"FAILED: {result['error']}", file=sys.stderr)
        sys.exit(1)
