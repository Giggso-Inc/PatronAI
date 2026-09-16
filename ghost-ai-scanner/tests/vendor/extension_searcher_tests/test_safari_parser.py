"""Safari parser, tested without macOS. PLAN.md section 12: ".appex tests
use a synthetic bundle directory with a real Info.plist" and "pluginkit is
invoked through an injected runner" — no real macOS host is touched or
required; this is exactly the gap flagged in PLAN.md section 15.1 (no
macOS host has verified this parser against a REAL install), which these
tests do not close, but they do lock in the parser's own logic.
"""

from __future__ import annotations

import plistlib
import subprocess

import pytest

from extension_searcher.parsers import safari


def _make_appex(app_dir, app_name: str, ext_name: str, info: dict) -> None:
    appex_dir = app_dir / f"{app_name}.app" / "Contents" / "PlugIns" / f"{ext_name}.appex"
    contents_dir = appex_dir / "Contents"
    contents_dir.mkdir(parents=True)
    with (contents_dir / "Info.plist").open("wb") as f:
        plistlib.dump(info, f)


@pytest.fixture
def macos_env(monkeypatch, tmp_path):
    monkeypatch.setattr(safari, "is_macos", lambda: True)
    monkeypatch.setattr(safari, "_APP_DIRS", (tmp_path,))
    monkeypatch.setattr(safari, "shutil", safari.shutil)  # keep real shutil.which behavior
    monkeypatch.setattr(safari.shutil, "which", lambda name: None)  # no pluginkit by default
    return tmp_path


def test_scan_finds_web_extension_via_appex_bundle(macos_env):
    _make_appex(
        macos_env,
        "FakeBrowser",
        "FakeExt",
        {
            "CFBundleIdentifier": "com.example.fakeext",
            "CFBundleDisplayName": "Fake Extension",
            "CFBundleShortVersionString": "1.2.3",
            "NSExtension": {"NSExtensionPointIdentifier": "com.apple.Safari.web-extension"},
        },
    )

    hit, records, errors = safari.scan()

    assert errors == []
    assert hit.found is True
    assert hit.unverified is True  # PLAN.md section 15.1 — always true, no macOS host to confirm
    assert len(records) == 1
    r = records[0]
    assert r.extension_id == "com.example.fakeext"
    assert r.name == "Fake Extension"
    assert r.version == "1.2.3"
    assert r.confidence.value == "partial"
    assert r.permissions == ()
    assert r.enabled is None  # no pluginkit available in this test


def test_scan_ignores_non_safari_extension_points(macos_env):
    _make_appex(
        macos_env,
        "FakeBrowser",
        "UnrelatedExt",
        {
            "CFBundleIdentifier": "com.example.unrelated",
            "NSExtension": {"NSExtensionPointIdentifier": "com.apple.share-services"},
        },
    )

    hit, records, errors = safari.scan()

    assert records == []
    assert hit.found is False


def test_scan_merges_pluginkit_enabled_state(macos_env, monkeypatch):
    _make_appex(
        macos_env,
        "FakeBrowser",
        "FakeExt",
        {
            "CFBundleIdentifier": "com.example.fakeext",
            "CFBundleDisplayName": "Fake Extension",
            "NSExtension": {"NSExtensionPointIdentifier": "com.apple.Safari.extension"},
        },
    )
    monkeypatch.setattr(safari.shutil, "which", lambda name: "/usr/bin/pluginkit")

    fake_result = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="+com.example.fakeext  1.0  some-uuid\n", stderr=""
    )
    monkeypatch.setattr(safari.subprocess, "run", lambda *a, **k: fake_result)

    hit, records, errors = safari.scan()

    assert len(records) == 1
    assert records[0].enabled is True
    assert records[0].state_source == "pluginkit"


def test_scan_handles_malformed_plist_as_error_not_crash(macos_env):
    appex_dir = macos_env / "FakeBrowser.app" / "Contents" / "PlugIns" / "Broken.appex" / "Contents"
    appex_dir.mkdir(parents=True)
    (appex_dir / "Info.plist").write_bytes(b"not a real plist")

    hit, records, errors = safari.scan()

    assert records == []
    assert len(errors) == 1
    assert errors[0].kind == "json_decode"
