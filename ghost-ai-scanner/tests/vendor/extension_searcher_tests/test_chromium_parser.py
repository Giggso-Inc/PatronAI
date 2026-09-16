"""PLAN.md section 12: regression coverage for two bugs found via live-host
testing on 2026-08-27 — builtin filtering leaking through the state-only
path, and the modern `disable_reasons`-only enabled-state fallback."""

from __future__ import annotations

import json

from extension_searcher.models import Engine, ProfileHit
from extension_searcher.parsers import chromium

EXT_ID = "abcdefghijklmnopabcdefghijklmnop"


def _make_profile(tmp_path, prefs: dict) -> ProfileHit:
    profile_dir = tmp_path / "Default"
    profile_dir.mkdir()
    (profile_dir / "Secure Preferences").write_text(
        json.dumps({"extensions": {"settings": prefs}}), encoding="utf-8"
    )
    return ProfileHit("Default", None, str(profile_dir), Engine.CHROMIUM)


def test_state_only_builtin_is_filtered_by_default(tmp_path):
    # A component extension (location=5) with no on-disk Extensions/<id>/
    # folder — the real shape found for Chrome PDF Viewer / Web Store on
    # this host: bundled under the browser install dir, not the profile.
    prefs = {
        EXT_ID: {
            "location": 5,
            "disable_reasons": [],
            "manifest": {"name": "Chrome PDF Viewer", "version": "1"},
        }
    }
    profile = _make_profile(tmp_path, prefs)

    records, errors = chromium.list_extensions(profile, "Google Chrome", "Stable")
    assert records == []

    records, errors = chromium.list_extensions(
        profile, "Google Chrome", "Stable", include_builtin=True
    )
    assert len(records) == 1
    assert records[0].is_builtin is True
    assert records[0].confidence.value == "state_only"


def test_enabled_state_falls_back_to_disable_reasons(tmp_path):
    # Modern Chrome (confirmed on Chrome 151): no `state` key, only
    # `disable_reasons`. Empty list means enabled.
    prefs = {
        EXT_ID: {
            "location": 1,
            "disable_reasons": [],
            "manifest": {"name": "Some Extension", "version": "2.0"},
        }
    }
    profile = _make_profile(tmp_path, prefs)

    records, _ = chromium.list_extensions(profile, "Google Chrome", "Stable")
    assert len(records) == 1
    assert records[0].enabled is True


def test_enabled_state_disabled_via_nonempty_disable_reasons(tmp_path):
    prefs = {
        EXT_ID: {
            "location": 1,
            "disable_reasons": [1],
            "manifest": {"name": "Some Extension", "version": "2.0"},
        }
    }
    profile = _make_profile(tmp_path, prefs)

    records, _ = chromium.list_extensions(profile, "Google Chrome", "Stable")
    assert len(records) == 1
    assert records[0].enabled is False


def test_legacy_state_field_takes_precedence(tmp_path):
    prefs = {
        EXT_ID: {
            "location": 1,
            "state": 0,
            "disable_reasons": [],  # would say "enabled" if state were ignored
            "manifest": {"name": "Legacy Extension", "version": "1.0"},
        }
    }
    profile = _make_profile(tmp_path, prefs)

    records, _ = chromium.list_extensions(profile, "Google Chrome", "Stable")
    assert len(records) == 1
    assert records[0].enabled is False


def test_full_ondisk_parse_happy_path(tmp_path):
    profile_dir = tmp_path / "Default"
    version_dir = profile_dir / "Extensions" / EXT_ID / "2.1.0_0"
    version_dir.mkdir(parents=True)
    manifest = {
        "name": "Real Extension",
        "version": "2.1.0",
        "description": "Does real things",
        "manifest_version": 3,
        "permissions": ["storage", "tabs"],
        "host_permissions": ["https://example.com/*"],
        "content_scripts": [{"matches": ["https://example.com/*"]}],
        "background": {"service_worker": "bg.js"},
        "update_url": "https://clients2.google.com/service/update2/crx",
    }
    (version_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    prefs = {
        EXT_ID: {
            "location": 1,
            "disable_reasons": [],
            "from_webstore": True,
            "install_time": "13205187002131396",
        }
    }
    (profile_dir / "Secure Preferences").write_text(
        json.dumps({"extensions": {"settings": prefs}}), encoding="utf-8"
    )
    profile = ProfileHit("Default", "Work", str(profile_dir), Engine.CHROMIUM)

    records, errors = chromium.list_extensions(profile, "Google Chrome", "Stable")

    assert errors == []
    assert len(records) == 1
    r = records[0]
    assert r.name == "Real Extension"
    assert r.version == "2.1.0"
    assert r.enabled is True
    assert r.install_origin.value == "webstore"
    assert r.permissions == ("storage", "tabs")
    assert r.host_permissions == ("https://example.com/*",)
    assert r.content_script_matches == ("https://example.com/*",)
    assert r.has_background_worker is True
    assert r.manifest_version == 3
    assert r.confidence.value == "full"
    assert r.install_time is not None and r.install_time.startswith("2019-")


def test_discover_profiles_uses_local_state_info_cache(tmp_path):
    default_dir = tmp_path / "Default"
    default_dir.mkdir()
    profile1_dir = tmp_path / "Profile 1"
    profile1_dir.mkdir()

    local_state = {
        "profile": {
            "info_cache": {
                "Default": {"name": "Work"},
                "Profile 1": {"name": "Personal"},
            }
        }
    }
    (tmp_path / "Local State").write_text(json.dumps(local_state), encoding="utf-8")

    profiles = chromium.discover_profiles(tmp_path)

    by_dir = {p.profile_dir: p.profile_name for p in profiles}
    assert by_dir == {"Default": "Work", "Profile 1": "Personal"}


def test_msg_name_resolved_via_locales(tmp_path):
    profile_dir = tmp_path / "Default"
    version_dir = profile_dir / "Extensions" / EXT_ID / "1.0_0"
    version_dir.mkdir(parents=True)
    manifest = {
        "name": "__MSG_extName__",
        "version": "1.0",
        "default_locale": "en_US",
        "manifest_version": 3,
    }
    (version_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    locales_dir = version_dir / "_locales" / "en_US"
    locales_dir.mkdir(parents=True)
    (locales_dir / "messages.json").write_text(
        json.dumps({"extName": {"message": "Localized Name"}}), encoding="utf-8"
    )
    profile = ProfileHit("Default", None, str(profile_dir), Engine.CHROMIUM)

    records, errors = chromium.list_extensions(profile, "Google Chrome", "Stable")

    assert errors == []
    assert len(records) == 1
    assert records[0].name == "Localized Name"
    assert records[0].warnings == ()


def test_discover_profiles_falls_back_without_local_state(tmp_path):
    default_dir = tmp_path / "Default"
    (default_dir / "Extensions").mkdir(parents=True)
    unrelated_dir = tmp_path / "Crash Reports"
    unrelated_dir.mkdir()

    profiles = chromium.discover_profiles(tmp_path)

    assert [p.profile_dir for p in profiles] == ["Default"]
