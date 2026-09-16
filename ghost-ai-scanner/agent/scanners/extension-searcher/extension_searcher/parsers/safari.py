"""Safari parser — macOS only. PLAN.md sections 5.3, 6.8.

UNVERIFIED (PLAN.md section 15.1): no macOS host has been available to
confirm this against a real install. Every record this parser produces is
`confidence=partial` — Safari extensions ship inside host apps with no
manifest to read, so name/ID/version/enabled state is the ceiling, by
platform design, not a parsing gap.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

from extension_searcher.errors import UnsupportedPlatformError
from extension_searcher.models import (
    BrowserHit,
    Confidence,
    Engine,
    ExtensionRecord,
    InstallOrigin,
    ScanError,
)
from extension_searcher.platform_probe import is_macos

logger = logging.getLogger(__name__)

_EXTENSION_POINT_IDS = frozenset(
    {
        "com.apple.Safari.extension",
        "com.apple.Safari.content-blocker",
        "com.apple.Safari.web-extension",
    }
)
_PLUGINKIT_QUERY_TYPES = (
    "com.apple.Safari.extension",
    "com.apple.Safari.content-blocker",
)
_APP_DIRS = (Path("/Applications"), Path.home() / "Applications")


def scan() -> tuple[BrowserHit, list[ExtensionRecord], list[ScanError]]:
    """Merge pluginkit (state) and .appex bundle scan (metadata). Section 6.8."""
    if not is_macos():
        raise UnsupportedPlatformError("Safari parser requires macOS")

    errors: list[ScanError] = []
    roots_checked = [str(d) for d in _APP_DIRS]

    bundles = _scan_appex_bundles(errors)
    enabled_by_id = _pluginkit_enabled_states(errors)

    records = [
        _build_record(bundle, enabled_by_id.get(bundle["bundle_id"]))
        for bundle in bundles
    ]

    hit = BrowserHit(
        "Safari",
        Engine.WEBKIT,
        found=bool(bundles),
        roots_checked=tuple(roots_checked),
        profiles=(),
        unverified=True,  # PLAN.md section 15.1 — no macOS host has verified this parser.
    )
    return hit, records, errors


def _scan_appex_bundles(errors: list[ScanError]) -> list[dict[str, Any]]:
    import plistlib

    bundles: list[dict[str, Any]] = []
    for app_dir in _APP_DIRS:
        if not app_dir.is_dir():
            continue
        try:
            apps = list(app_dir.iterdir())
        except OSError as exc:
            errors.append(ScanError(str(app_dir), "access_denied", str(exc)))
            continue
        for app in apps:
            if app.suffix != ".app":
                continue
            plugins_dir = app / "Contents" / "PlugIns"
            if not plugins_dir.is_dir():
                continue
            try:
                appexes = [p for p in plugins_dir.iterdir() if p.suffix == ".appex"]
            except OSError:
                continue
            for appex in appexes:
                info_plist = appex / "Contents" / "Info.plist"
                if not info_plist.is_file():
                    continue
                try:
                    with info_plist.open("rb") as f:
                        data = plistlib.load(f)
                except (OSError, ValueError) as exc:
                    errors.append(ScanError(str(info_plist), "json_decode", str(exc)))
                    continue

                extension_attrs = data.get("NSExtension", {}) or {}
                point_id = extension_attrs.get("NSExtensionPointIdentifier")
                if point_id not in _EXTENSION_POINT_IDS:
                    continue

                bundles.append(
                    {
                        "bundle_id": data.get("CFBundleIdentifier", appex.stem),
                        "name": (
                            data.get("CFBundleDisplayName")
                            or data.get("CFBundleName")
                            or appex.stem
                        ),
                        "version": data.get("CFBundleShortVersionString")
                        or data.get("CFBundleVersion")
                        or "unknown",
                        "host_app": app.stem,
                        "path": str(appex),
                        "mac_app_store": (app / "_MASReceipt" / "receipt").is_file(),
                    }
                )
    return bundles


def _pluginkit_enabled_states(errors: list[ScanError]) -> dict[str, bool]:
    """PLAN.md section 6.8 Source A: `pluginkit` output, `+`/`-`/`!` state flags."""
    states: dict[str, bool] = {}
    pluginkit_path = shutil.which("pluginkit")
    if not pluginkit_path:
        logger.warning("pluginkit not found on PATH")
        return states

    for ext_type in _PLUGINKIT_QUERY_TYPES:
        try:
            result = subprocess.run(
                [pluginkit_path, "-mAvvv", "-p", ext_type],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(ScanError(f"pluginkit -p {ext_type}", "external_tool_failed", str(exc)))
            continue

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line[0] not in "+-!":
                continue
            parts = line[1:].strip().split()
            if not parts:
                continue
            bundle_id = parts[0]
            states[bundle_id] = line[0] == "+"

    return states


def _build_record(bundle: dict[str, Any], enabled: bool | None) -> ExtensionRecord:
    origin = InstallOrigin.MAC_APP_STORE if bundle["mac_app_store"] else InstallOrigin.UNKNOWN
    return ExtensionRecord(
        extension_id=bundle["bundle_id"],
        name=bundle["name"],
        version=bundle["version"],
        description=None,
        browser="Safari",
        browser_channel=None,
        engine=Engine.WEBKIT,
        profile_dir=bundle["host_app"],
        profile_name=None,
        install_path=bundle["path"],
        enabled=enabled,
        disabled_reason=None,
        state_source="pluginkit" if enabled is not None else "appex_bundle_only",
        install_origin=origin,
        update_url=None,
        signed_state=None,
        is_builtin=False,
        is_unpacked=False,
        manifest_version=None,
        permissions=(),
        host_permissions=(),
        content_script_matches=(),
        has_background_worker=None,
        install_time=None,
        update_time=None,
        source_files=(bundle["path"],),
        confidence=Confidence.PARTIAL,
        warnings=(),
    )
