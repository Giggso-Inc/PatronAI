"""Origin/builtin classification. PLAN.md sections 6.5 and 6.7."""

from __future__ import annotations

from extension_searcher.models import InstallOrigin
from extension_searcher.normalize import (
    classify_chromium_origin,
    classify_gecko_origin,
    is_chromium_builtin,
    is_gecko_builtin,
)


def test_chromium_policy_location_wins():
    origin = classify_chromium_origin(
        update_url="https://clients2.google.com/service/update2/crx",
        from_webstore=True,
        location=9,
        has_absolute_path=False,
    )
    assert origin == InstallOrigin.POLICY


def test_chromium_component_is_builtin():
    origin = classify_chromium_origin(
        update_url=None, from_webstore=False, location=5, has_absolute_path=False
    )
    assert origin == InstallOrigin.BUILTIN
    assert is_chromium_builtin(5) is True
    assert is_chromium_builtin(1) is False


def test_chromium_absolute_path_is_unpacked_even_with_webstore_url():
    origin = classify_chromium_origin(
        update_url="https://clients2.google.com/service/update2/crx",
        from_webstore=False,
        location=None,
        has_absolute_path=True,
    )
    assert origin == InstallOrigin.UNPACKED


def test_chromium_webstore_update_url():
    origin = classify_chromium_origin(
        update_url="https://clients2.google.com/service/update2/crx",
        from_webstore=False,
        location=None,
        has_absolute_path=False,
    )
    assert origin == InstallOrigin.WEBSTORE


def test_chromium_non_webstore_update_url_is_sideloaded():
    origin = classify_chromium_origin(
        update_url="https://example.com/update.xml",
        from_webstore=False,
        location=None,
        has_absolute_path=False,
    )
    assert origin == InstallOrigin.SIDELOADED


def test_chromium_nothing_known_is_unknown():
    origin = classify_chromium_origin(
        update_url=None, from_webstore=None, location=None, has_absolute_path=False
    )
    assert origin == InstallOrigin.UNKNOWN


def test_chromium_unrecognized_location_falls_through_safely():
    # PLAN.md edge case 17: unknown enum values must never raise.
    origin = classify_chromium_origin(
        update_url=None, from_webstore=False, location=999, has_absolute_path=False
    )
    assert origin == InstallOrigin.UNKNOWN


def test_gecko_amo_origin():
    origin = classify_gecko_origin(
        source_uri="https://addons.mozilla.org/firefox/downloads/x.xpi", location="app-profile"
    )
    assert origin == InstallOrigin.AMO


def test_gecko_builtin_location():
    origin = classify_gecko_origin(source_uri=None, location="app-builtin")
    assert origin == InstallOrigin.BUILTIN
    assert is_gecko_builtin("app-builtin") is True
    assert is_gecko_builtin("app-profile") is False


def test_gecko_sideloaded_when_non_amo_source():
    origin = classify_gecko_origin(source_uri="https://example.com/x.xpi", location="app-profile")
    assert origin == InstallOrigin.SIDELOADED


def test_gecko_unknown_when_nothing_known():
    origin = classify_gecko_origin(source_uri=None, location=None)
    assert origin == InstallOrigin.UNKNOWN
