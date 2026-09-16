"""Chromium engine parser. PLAN.md sections 6.1-6.5.

Profile discovery reads `Local State`; extension enumeration reads the fixed
`Extensions/<id>/<version>/manifest.json` layout directly (never recursed —
PLAN.md section 7, rule 2); state (enabled/disabled, install time, origin)
comes from `Secure Preferences` / `Preferences`, read once per profile and
cached (PLAN.md section 7, rule 6).
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from extension_searcher.enrich import chromium_time_to_iso, resolve_localized_name
from extension_searcher.errors import ManifestParseError
from extension_searcher.models import Confidence, Engine, ExtensionRecord, ProfileHit, ScanError
from extension_searcher.normalize import classify_chromium_origin, is_chromium_builtin

logger = logging.getLogger(__name__)

_EXTENSION_ID_RE = re.compile(r"^[a-p]{32}$")
_PROFILE_DIR_RE = re.compile(r"^Profile \d+$")
_MAX_JSON_BYTES = 25 * 1024 * 1024  # PLAN.md section 7, rule 9


def discover_profiles(user_data_root: Path) -> list[ProfileHit]:
    """PLAN.md section 6.1: prefer `Local State`, fall back to scandir."""
    profiles: list[ProfileHit] = []
    local_state = _read_json_safe(user_data_root / "Local State")
    seen_dirs: set[str] = set()

    if local_state:
        info_cache = local_state.get("profile", {}).get("info_cache", {})
        if isinstance(info_cache, dict):
            for dir_name, info in info_cache.items():
                profile_path = user_data_root / dir_name
                if not profile_path.is_dir():
                    continue
                name = info.get("name") if isinstance(info, dict) else None
                profiles.append(ProfileHit(dir_name, name, str(profile_path), Engine.CHROMIUM))
                seen_dirs.add(dir_name)

    if not profiles:
        try:
            for entry in user_data_root.iterdir():
                if not entry.is_dir() or entry.name in seen_dirs:
                    continue
                is_candidate = (
                    entry.name == "Default"
                    or _PROFILE_DIR_RE.match(entry.name)
                    or entry.name in ("Guest Profile", "System Profile")
                )
                if is_candidate and (entry / "Extensions").is_dir():
                    profiles.append(ProfileHit(entry.name, None, str(entry), Engine.CHROMIUM))
        except OSError:
            logger.warning("Failed to scan %s", user_data_root, exc_info=True)

    return profiles


def list_extensions(
    profile: ProfileHit,
    browser_name: str,
    browser_channel: str | None,
    *,
    include_builtin: bool = False,
    include_state: bool = True,
) -> tuple[list[ExtensionRecord], list[ScanError]]:
    """PLAN.md section 6.2-6.5: enumerate, parse, and state-enrich.

    `include_state=False` (CLI `--no-state`) skips the `Preferences` /
    `Secure Preferences` read entirely — PLAN.md section 7, rule 6 notes
    that blob as the dominant per-profile cost, so this is the fastest
    possible run. Orphan/state-only records are unavailable in this mode,
    since they only exist in the skipped preferences blob.
    """
    profile_path = Path(profile.path)
    records: list[ExtensionRecord] = []
    errors: list[ScanError] = []

    prefs = _load_merged_preferences(profile_path) if include_state else {}

    extensions_dir = profile_path / "Extensions"
    on_disk_ids: set[str] = set()
    if extensions_dir.is_dir():
        try:
            entries = list(extensions_dir.iterdir())
        except OSError as exc:
            errors.append(ScanError(str(extensions_dir), "access_denied", str(exc)))
            entries = []

        for ext_dir in entries:
            if not ext_dir.is_dir():
                continue
            ext_id = ext_dir.name
            if not _EXTENSION_ID_RE.match(ext_id):
                continue
            on_disk_ids.add(ext_id)
            try:
                record = _parse_on_disk_extension(
                    ext_dir, ext_id, profile, browser_name, browser_channel,
                    prefs.get(ext_id, {}),
                )
            except ManifestParseError as exc:
                errors.append(ScanError(str(ext_dir), exc.kind, str(exc)))
                continue
            except OSError as exc:
                errors.append(ScanError(str(ext_dir), "access_denied", str(exc)))
                continue
            if record is None:
                continue
            if record.is_builtin and not include_builtin:
                continue
            records.append(record)

    # State-only records: a prefs entry exists with no matching folder under
    # <profile>/Extensions/. Two real cases hit this, both covered by PLAN.md
    # 6.5 / edge case 4: the extension folder was deleted, OR (the common
    # case, found via the live smoke test against this host) the extension
    # is a browser-bundled component installed under the browser's own
    # install directory (e.g. Chrome PDF Viewer under Program Files), never
    # under the profile at all. Both get confidence=state_only; the builtin
    # filter must still apply here — it is not exclusive to the on-disk path.
    for ext_id, settings in prefs.items():
        if ext_id in on_disk_ids or not _EXTENSION_ID_RE.match(ext_id):
            continue
        record = _build_state_only_record(
            ext_id, profile, browser_name, browser_channel, settings
        )
        if record is None:
            continue
        if record.is_builtin and not include_builtin:
            continue
        records.append(record)

    return records, errors


def _load_merged_preferences(profile_path: Path) -> dict[str, dict[str, Any]]:
    """Merge `Preferences` and `Secure Preferences`, preferring the latter."""
    merged: dict[str, dict[str, Any]] = {}
    for filename in ("Preferences", "Secure Preferences"):
        data = _read_json_safe(profile_path / filename)
        if not data:
            continue
        settings = data.get("extensions", {}).get("settings", {})
        if isinstance(settings, dict):
            for ext_id, entry in settings.items():
                if isinstance(entry, dict):
                    merged[ext_id] = entry
    return merged


def _read_json_safe(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        if path.stat().st_size > _MAX_JSON_BYTES:
            logger.warning("Skipping oversized JSON: %s", path)
            return None
    except OSError:
        return None
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _derive_enabled(prefs_entry: dict[str, Any]) -> bool | None:
    """Enabled/disabled from a prefs settings entry.

    PLAN.md section 6.5 documented `state` (1/0) as the enabled signal. Live
    testing against Chrome 151 found that field absent from recently-written
    profile entries entirely — current Chrome instead relies on
    `disable_reasons` (a list; empty means enabled). Older, long-lived
    profile entries can still carry the legacy `state` field, so both are
    checked, `state` first for backward compatibility.
    """
    state = prefs_entry.get("state")
    if state is not None:
        return bool(state == 1)
    disable_reasons = prefs_entry.get("disable_reasons")
    if disable_reasons is not None:
        return len(disable_reasons) == 0
    return None


def _highest_version_dir(ext_dir: Path) -> Path | None:
    try:
        version_dirs = [d for d in ext_dir.iterdir() if d.is_dir()]
    except OSError:
        return None
    if not version_dirs:
        return None

    def sort_key(d: Path) -> tuple[int, ...]:
        base = d.name.split("_", 1)[0]
        parts = []
        for chunk in base.split("."):
            try:
                parts.append(int(chunk))
            except ValueError:
                parts.append(0)
        return tuple(parts)

    return max(version_dirs, key=sort_key)


def _parse_on_disk_extension(
    ext_dir: Path,
    ext_id: str,
    profile: ProfileHit,
    browser_name: str,
    browser_channel: str | None,
    prefs_entry: dict[str, Any],
) -> ExtensionRecord | None:
    version_dir = _highest_version_dir(ext_dir)
    if version_dir is None:
        return None
    manifest_path = version_dir / "manifest.json"
    manifest = _read_json_safe(manifest_path)
    if manifest is None:
        if not manifest_path.exists():
            return None
        raise ManifestParseError(f"Could not parse {manifest_path}")

    warnings: list[str] = []
    raw_name = manifest.get("name", ext_id)
    default_locale = manifest.get("default_locale")
    name, locale_warnings = resolve_localized_name(raw_name, version_dir, default_locale)
    warnings.extend(locale_warnings)

    location = prefs_entry.get("location")
    install_path = prefs_entry.get("path") or str(version_dir)
    has_absolute_path = bool(prefs_entry.get("path")) and Path(prefs_entry["path"]).is_absolute()

    enabled = _derive_enabled(prefs_entry)
    disable_reasons = prefs_entry.get("disable_reasons")

    permissions = tuple(manifest.get("permissions", []) or [])
    manifest_permissions = manifest.get("permissions", []) or []
    host_permissions = tuple(
        manifest.get("host_permissions")
        or [p for p in manifest_permissions if "://" in str(p) or p == "<all_urls>"]
    )
    content_scripts = manifest.get("content_scripts", []) or []
    content_matches = tuple(
        m for cs in content_scripts if isinstance(cs, dict) for m in cs.get("matches", [])
    )
    background = manifest.get("background", {}) or {}
    has_background = bool(background.get("service_worker") or background.get("scripts"))

    is_builtin = is_chromium_builtin(location)
    origin = classify_chromium_origin(
        update_url=manifest.get("update_url"),
        from_webstore=prefs_entry.get("from_webstore"),
        location=location,
        has_absolute_path=has_absolute_path,
    )

    return ExtensionRecord(
        extension_id=ext_id,
        name=name,
        version=str(manifest.get("version", version_dir.name)),
        description=manifest.get("description"),
        browser=browser_name,
        browser_channel=browser_channel,
        engine=Engine.CHROMIUM,
        profile_dir=profile.profile_dir,
        profile_name=profile.profile_name,
        install_path=install_path,
        enabled=enabled,
        disabled_reason=str(disable_reasons) if disable_reasons else None,
        state_source="secure_preferences" if prefs_entry else "manifest_only",
        install_origin=origin,
        update_url=manifest.get("update_url"),
        signed_state=None,
        is_builtin=is_builtin,
        is_unpacked=has_absolute_path,
        manifest_version=manifest.get("manifest_version"),
        permissions=permissions,
        host_permissions=host_permissions,
        content_script_matches=content_matches,
        has_background_worker=has_background,
        install_time=chromium_time_to_iso(prefs_entry.get("install_time")),
        update_time=None,
        source_files=(str(manifest_path),),
        confidence=Confidence.FULL,
        warnings=tuple(warnings),
    )


def _build_state_only_record(
    ext_id: str,
    profile: ProfileHit,
    browser_name: str,
    browser_channel: str | None,
    prefs_entry: dict[str, Any],
) -> ExtensionRecord | None:
    cached_manifest = prefs_entry.get("manifest")
    if not isinstance(cached_manifest, dict):
        return None

    enabled = _derive_enabled(prefs_entry)
    location = prefs_entry.get("location")
    disable_reasons = prefs_entry.get("disable_reasons")
    origin = classify_chromium_origin(
        update_url=cached_manifest.get("update_url"),
        from_webstore=prefs_entry.get("from_webstore"),
        location=location,
        has_absolute_path=False,
    )

    return ExtensionRecord(
        extension_id=ext_id,
        name=str(cached_manifest.get("name", ext_id)),
        version=str(cached_manifest.get("version", "unknown")),
        description=cached_manifest.get("description"),
        browser=browser_name,
        browser_channel=browser_channel,
        engine=Engine.CHROMIUM,
        profile_dir=profile.profile_dir,
        profile_name=profile.profile_name,
        install_path=prefs_entry.get("path", "unknown"),
        enabled=enabled,
        disabled_reason=str(disable_reasons) if disable_reasons else None,
        state_source="secure_preferences",
        install_origin=origin,
        update_url=cached_manifest.get("update_url"),
        signed_state=None,
        is_builtin=is_chromium_builtin(location),
        is_unpacked=False,
        manifest_version=cached_manifest.get("manifest_version"),
        permissions=tuple(cached_manifest.get("permissions", []) or []),
        host_permissions=tuple(cached_manifest.get("host_permissions", []) or []),
        content_script_matches=(),
        has_background_worker=None,
        install_time=chromium_time_to_iso(prefs_entry.get("install_time")),
        update_time=None,
        source_files=(),
        confidence=Confidence.STATE_ONLY,
        warnings=("extension_folder_missing",),
    )
