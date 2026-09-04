"""Shared classification helpers used while building `ExtensionRecord`s.

PLAN.md section 6.5 (Chromium origin/location) and 6.7 (Gecko origin/
location) — kept here so both parsers classify the same way.
"""

from __future__ import annotations

from extension_searcher.models import InstallOrigin

_CHROME_WEBSTORE_UPDATE_URL = "clients2.google.com/service/update2/crx"

# Chromium Manifest::Location enum values relevant to origin classification.
# PLAN.md 6.5 flags this table as needing verification against the Chromium
# source for the target version — unknown values fall through to UNKNOWN
# rather than raising (edge case 17).
_CHROMIUM_POLICY_LOCATIONS = frozenset({7, 9, 10})
_CHROMIUM_COMPONENT_LOCATIONS = frozenset({5})
_CHROMIUM_UNPACKED_LOCATIONS = frozenset({4})

# Gecko `location` values that mark a browser-shipped (builtin) addon.
_GECKO_BUILTIN_LOCATIONS = frozenset({"app-builtin", "app-system-defaults", "app-global"})


def classify_chromium_origin(
    *,
    update_url: str | None,
    from_webstore: bool | None,
    location: int | None,
    has_absolute_path: bool,
) -> InstallOrigin:
    if location in _CHROMIUM_POLICY_LOCATIONS:
        return InstallOrigin.POLICY
    if location in _CHROMIUM_COMPONENT_LOCATIONS:
        return InstallOrigin.BUILTIN
    if location in _CHROMIUM_UNPACKED_LOCATIONS or has_absolute_path:
        return InstallOrigin.UNPACKED
    if from_webstore:
        return InstallOrigin.WEBSTORE
    if update_url and _CHROME_WEBSTORE_UPDATE_URL in update_url:
        return InstallOrigin.WEBSTORE
    if update_url:
        return InstallOrigin.SIDELOADED
    return InstallOrigin.UNKNOWN


def classify_gecko_origin(*, source_uri: str | None, location: str | None) -> InstallOrigin:
    if location in _GECKO_BUILTIN_LOCATIONS:
        return InstallOrigin.BUILTIN
    if source_uri and "addons.mozilla.org" in source_uri:
        return InstallOrigin.AMO
    if source_uri:
        return InstallOrigin.SIDELOADED
    return InstallOrigin.UNKNOWN


def is_chromium_builtin(location: int | None) -> bool:
    return location in _CHROMIUM_COMPONENT_LOCATIONS


def is_gecko_builtin(location: str | None) -> bool:
    return location in _GECKO_BUILTIN_LOCATIONS
