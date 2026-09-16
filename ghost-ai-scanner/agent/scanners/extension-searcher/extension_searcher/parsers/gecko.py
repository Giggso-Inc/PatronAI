"""Gecko engine parser. PLAN.md sections 6.6-6.7.

Profile discovery reads `profiles.ini` via `configparser`; extension
enumeration reads the single `extensions.json` per profile — Gecko
pre-resolves locale names, so there is no `__MSG_*` problem here
(unlike Chromium, section 6.4).
"""

from __future__ import annotations

import configparser
import json
import logging
from pathlib import Path
from typing import Any

from extension_searcher.enrich import gecko_time_to_iso
from extension_searcher.models import Confidence, Engine, ExtensionRecord, ProfileHit
from extension_searcher.normalize import classify_gecko_origin, is_gecko_builtin

logger = logging.getLogger(__name__)

_SKIP_ADDON_TYPES = frozenset({"theme", "dictionary", "locale", "sitepermission"})


def _profile_matches_channel(name: str | None, rel_path: str | None, channel: str | None) -> bool:
    """Heuristic channel disambiguation for a shared `profiles.ini` root.

    PLAN.md section 6.6 point 3 notes that Firefox, Developer Edition, and
    Nightly can share one `profiles.ini` root, with `installs.ini` mapping
    each install to its own default profile. Fully resolving that mapping
    needs the install (executable) path, which this tool's browser-data-only
    discovery does not model. Live testing on this host confirmed the real
    failure mode without any disambiguation: probing the same shared root
    once per channel spec tripled every Firefox profile and extension in
    the default output. This name/path heuristic is the interim fix — not
    as precise as `installs.ini`, but it stops the triple-counting.
    """
    if channel is None:
        return True
    combined = f"{name or ''} {rel_path or ''}".lower()
    if channel == "Dev":
        return "dev-edition" in combined
    if channel == "Nightly":
        return "nightly" in combined
    if channel == "Stable":
        return "dev-edition" not in combined and "nightly" not in combined
    return True


def discover_profiles(gecko_root: Path, channel: str | None = None) -> list[ProfileHit]:
    """PLAN.md section 6.6: profiles.ini, falling back to a directory scan.

    The fallback only fires when `profiles.ini` itself is missing or
    unreadable — not merely when channel filtering left zero matches. Live
    testing found that distinction matters: a channel-blind fallback that
    also triggered on "ini parsed fine, but 0 profiles for this channel"
    silently re-added every profile it had just correctly filtered out.
    """
    profiles: list[ProfileHit] = []
    ini_path = gecko_root / "profiles.ini"
    ini_read_ok = False

    if ini_path.is_file():
        parser = configparser.ConfigParser()
        try:
            parser.read(ini_path, encoding="utf-8")
        except (OSError, configparser.Error):
            logger.warning("Failed to parse %s", ini_path, exc_info=True)
        else:
            ini_read_ok = True
            for section in parser.sections():
                if not section.startswith("Profile"):
                    continue
                items = parser[section]
                rel_path = items.get("Path")
                if not rel_path:
                    continue
                if not _profile_matches_channel(items.get("Name"), rel_path, channel):
                    continue
                is_relative = items.get("IsRelative", "1") == "1"
                profile_path = (gecko_root / rel_path) if is_relative else Path(rel_path)
                if not profile_path.is_dir():
                    continue
                profiles.append(
                    ProfileHit(
                        profile_path.name, items.get("Name"), str(profile_path), Engine.GECKO
                    )
                )

    if not profiles and not ini_read_ok:
        profiles_dir = gecko_root / "Profiles"
        if profiles_dir.is_dir():
            try:
                for entry in profiles_dir.iterdir():
                    if not entry.is_dir() or "default" not in entry.name:
                        continue
                    if not _profile_matches_channel(None, entry.name, channel):
                        continue
                    profiles.append(ProfileHit(entry.name, None, str(entry), Engine.GECKO))
            except OSError:
                logger.warning("Failed to scan %s", profiles_dir, exc_info=True)

    return profiles


def list_extensions(
    profile: ProfileHit,
    browser_name: str,
    browser_channel: str | None,
    *,
    include_builtin: bool = False,
    include_themes: bool = False,
) -> list[ExtensionRecord]:
    """PLAN.md section 6.7: parse `extensions.json`'s `addons[]` array."""
    ext_json_path = Path(profile.path) / "extensions.json"
    data = _read_json_safe(ext_json_path)
    if data is None:
        return []

    addons = data.get("addons", [])
    if not isinstance(addons, list):
        return []

    records: list[ExtensionRecord] = []
    for addon in addons:
        if not isinstance(addon, dict):
            continue
        addon_type = addon.get("type", "extension")
        if addon_type in _SKIP_ADDON_TYPES and not include_themes:
            continue

        location = addon.get("location")
        is_builtin = is_gecko_builtin(location)
        if is_builtin and not include_builtin:
            continue

        record = _build_record(
            addon, profile, browser_name, browser_channel, str(ext_json_path), is_builtin
        )
        if record is not None:
            records.append(record)

    return records


def _read_json_safe(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        logger.warning("Failed to parse %s", path, exc_info=True)
        return None
    return data if isinstance(data, dict) else None


def _build_record(
    addon: dict[str, Any],
    profile: ProfileHit,
    browser_name: str,
    browser_channel: str | None,
    source_file: str,
    is_builtin: bool,
) -> ExtensionRecord | None:
    ext_id = addon.get("id")
    if not ext_id:
        return None

    default_locale = addon.get("defaultLocale", {}) or {}
    name = default_locale.get("name") or ext_id
    description = default_locale.get("description")

    user_disabled = addon.get("userDisabled", False)
    app_disabled = addon.get("appDisabled", False)
    soft_disabled = addon.get("softDisabled", False)
    active = addon.get("active")
    enabled: bool | None
    if active is not None:
        enabled = bool(active)
    else:
        enabled = not (user_disabled or app_disabled or soft_disabled)

    disabled_reason = None
    if not enabled:
        reasons = [
            r for r, flag in (
                ("user_disabled", user_disabled),
                ("app_disabled", app_disabled),
                ("soft_disabled", soft_disabled),
            ) if flag
        ]
        disabled_reason = ",".join(reasons) or None

    source_uri = addon.get("sourceURI")
    location = addon.get("location")
    origin = classify_gecko_origin(source_uri=source_uri, location=location)

    permissions_block = addon.get("userPermissions", {}) or {}
    permissions = tuple(permissions_block.get("permissions", []) or [])
    origins = tuple(permissions_block.get("origins", []) or [])

    signed_state_raw = addon.get("signedState")
    signed_state = str(signed_state_raw) if signed_state_raw is not None else None

    return ExtensionRecord(
        extension_id=str(ext_id),
        name=str(name),
        version=str(addon.get("version", "unknown")),
        description=description,
        browser=browser_name,
        browser_channel=browser_channel,
        engine=Engine.GECKO,
        profile_dir=profile.profile_dir,
        profile_name=profile.profile_name,
        install_path=addon.get("rootURI", "unknown"),
        enabled=enabled,
        disabled_reason=disabled_reason,
        state_source="extensions_json",
        install_origin=origin,
        update_url=addon.get("updateURL"),
        signed_state=signed_state,
        is_builtin=is_builtin,
        is_unpacked=False,
        manifest_version=None,
        permissions=permissions,
        host_permissions=origins,
        content_script_matches=(),
        has_background_worker=None,
        install_time=gecko_time_to_iso(addon.get("installDate")),
        update_time=gecko_time_to_iso(addon.get("updateDate")),
        source_files=(source_file,),
        confidence=Confidence.FULL,
        warnings=(),
    )
