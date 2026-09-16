"""PLAN.md section 12: regression coverage for the Firefox/Dev-Edition/
Nightly triple-counting bug found via live-host testing on 2026-08-27 —
all three channels can share one `profiles.ini` root."""

from __future__ import annotations

import json

from extension_searcher.models import Engine, ProfileHit
from extension_searcher.parsers import gecko

PROFILES_INI = """
[Profile0]
Name=default
IsRelative=1
Path={release}

[Profile1]
Name=dev-edition-default
IsRelative=1
Path={dev}
"""


def _make_gecko_root(tmp_path):
    release_dir = tmp_path / "abc.default-release"
    dev_dir = tmp_path / "def.dev-edition-default"
    release_dir.mkdir()
    dev_dir.mkdir()
    ini = PROFILES_INI.format(release=release_dir.name, dev=dev_dir.name)
    (tmp_path / "profiles.ini").write_text(ini, encoding="utf-8")
    return tmp_path


def test_shared_root_channels_do_not_duplicate(tmp_path):
    root = _make_gecko_root(tmp_path)

    stable = gecko.discover_profiles(root, channel="Stable")
    dev = gecko.discover_profiles(root, channel="Dev")
    nightly = gecko.discover_profiles(root, channel="Nightly")

    assert [p.profile_dir for p in stable] == ["abc.default-release"]
    assert [p.profile_dir for p in dev] == ["def.dev-edition-default"]
    assert nightly == []  # no nightly profile exists in this fixture


def test_no_channel_filter_returns_everything(tmp_path):
    root = _make_gecko_root(tmp_path)
    all_profiles = gecko.discover_profiles(root, channel=None)
    assert len(all_profiles) == 2


def test_fallback_scan_respects_channel_when_ini_absent(tmp_path):
    # No profiles.ini at all -> directory-scan fallback must still filter.
    (tmp_path / "Profiles").mkdir()
    (tmp_path / "Profiles" / "xyz.default-release").mkdir()
    (tmp_path / "Profiles" / "xyz.dev-edition-default").mkdir()

    stable = gecko.discover_profiles(tmp_path, channel="Stable")
    dev = gecko.discover_profiles(tmp_path, channel="Dev")

    assert [p.profile_dir for p in stable] == ["xyz.default-release"]
    assert [p.profile_dir for p in dev] == ["xyz.dev-edition-default"]


def test_full_extensions_json_parse_happy_path(tmp_path):
    profile_dir = tmp_path / "abc.default-release"
    profile_dir.mkdir()
    addons = {
        "addons": [
            {
                "id": "myext@example.com",
                "type": "extension",
                "version": "3.2.1",
                "active": True,
                "userDisabled": False,
                "appDisabled": False,
                "defaultLocale": {"name": "My Extension", "description": "Does things"},
                "sourceURI": "https://addons.mozilla.org/firefox/downloads/x.xpi",
                "location": "app-profile",
                "rootURI": "jar:file:///profile/extensions/myext.xpi!/",
                "signedState": 2,
                "installDate": 1700000000000,
                "updateDate": 1700000001000,
                "userPermissions": {
                    "permissions": ["storage", "tabs"],
                    "origins": ["https://example.com/*"],
                },
            },
            {
                "id": "builtin@mozilla.org",
                "type": "extension",
                "version": "1.0",
                "active": True,
                "location": "app-builtin",
            },
            {
                "id": "sometheme@mozilla.org",
                "type": "theme",
                "version": "1.0",
                "active": False,
            },
        ]
    }
    (profile_dir / "extensions.json").write_text(json.dumps(addons), encoding="utf-8")
    profile = ProfileHit("abc.default-release", "default-release", str(profile_dir), Engine.GECKO)

    records = gecko.list_extensions(profile, "Mozilla Firefox", "Stable")

    # Builtin excluded by default, theme excluded by default -> only the real extension.
    assert len(records) == 1
    r = records[0]
    assert r.extension_id == "myext@example.com"
    assert r.name == "My Extension"
    assert r.version == "3.2.1"
    assert r.enabled is True
    assert r.install_origin.value == "amo"
    assert r.is_builtin is False
    assert r.permissions == ("storage", "tabs")
    assert r.host_permissions == ("https://example.com/*",)
    assert r.signed_state == "2"
    assert r.install_time is not None and r.install_time.startswith("2023-11-14")


def test_disabled_addon_reports_reason(tmp_path):
    profile_dir = tmp_path / "abc.default-release"
    profile_dir.mkdir()
    addons = {
        "addons": [
            {
                "id": "disabled@example.com",
                "type": "extension",
                "version": "1.0",
                "active": False,
                "userDisabled": True,
                "location": "app-profile",
            }
        ]
    }
    (profile_dir / "extensions.json").write_text(json.dumps(addons), encoding="utf-8")
    profile = ProfileHit("abc.default-release", None, str(profile_dir), Engine.GECKO)

    records = gecko.list_extensions(profile, "Mozilla Firefox", "Stable")

    assert len(records) == 1
    assert records[0].enabled is False
    assert records[0].disabled_reason == "user_disabled"
