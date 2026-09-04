"""Root resolution across OSes. PLAN.md section 5: a root kind must resolve
to None (not raise, not resolve to the wrong OS's path) when asked for on
an OS it doesn't apply to."""

from __future__ import annotations

import sys
import types

from extension_searcher import platform_probe
from extension_searcher.registry import RootKind


def test_win_localappdata_resolves_on_windows(monkeypatch):
    monkeypatch.setattr(platform_probe, "current_os", lambda: "windows")
    monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\Test\AppData\Local")
    result = platform_probe.resolve_root(RootKind.WIN_LOCALAPPDATA)
    assert str(result) == r"C:\Users\Test\AppData\Local"


def test_win_localappdata_is_none_on_other_os(monkeypatch):
    monkeypatch.setattr(platform_probe, "current_os", lambda: "linux")
    assert platform_probe.resolve_root(RootKind.WIN_LOCALAPPDATA) is None


def test_mac_app_support_resolves_only_on_macos(monkeypatch):
    monkeypatch.setattr(platform_probe, "current_os", lambda: "macos")
    result = platform_probe.resolve_root(RootKind.MAC_APP_SUPPORT)
    assert result is not None
    assert result.name == "Application Support"

    monkeypatch.setattr(platform_probe, "current_os", lambda: "windows")
    assert platform_probe.resolve_root(RootKind.MAC_APP_SUPPORT) is None


def test_linux_config_honours_xdg_config_home(monkeypatch, tmp_path):
    monkeypatch.setattr(platform_probe, "current_os", lambda: "linux")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    result = platform_probe.resolve_root(RootKind.LINUX_CONFIG)
    assert result == tmp_path


def test_linux_config_defaults_to_dot_config_when_xdg_unset(monkeypatch):
    monkeypatch.setattr(platform_probe, "current_os", lambda: "linux")
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    result = platform_probe.resolve_root(RootKind.LINUX_CONFIG)
    assert result is not None
    assert result.name == ".config"


def test_home_resolves_on_any_os(monkeypatch):
    for os_name in ("windows", "macos", "linux"):
        monkeypatch.setattr(platform_probe, "current_os", lambda os_name=os_name: os_name)
        assert platform_probe.resolve_root(RootKind.HOME) is not None


def test_installed_browser_hints_never_raises(monkeypatch):
    # Whatever OS this actually runs on, the probe must degrade gracefully.
    result = platform_probe.installed_browser_hints()
    assert isinstance(result, frozenset)


def test_installed_browser_hints_dispatches_by_os(monkeypatch):
    for os_name, fn_name in (
        ("windows", "_windows_installed_hints"),
        ("macos", "_macos_installed_hints"),
        ("linux", "_linux_installed_hints"),
    ):
        monkeypatch.setattr(platform_probe, "current_os", lambda os_name=os_name: os_name)
        monkeypatch.setattr(platform_probe, fn_name, lambda: frozenset({"marker"}))
        assert platform_probe.installed_browser_hints() == frozenset({"marker"})


def test_installed_browser_hints_swallows_os_errors(monkeypatch):
    monkeypatch.setattr(platform_probe, "current_os", lambda: "windows")

    def _raise():
        raise OSError("registry unavailable")

    monkeypatch.setattr(platform_probe, "_windows_installed_hints", _raise)
    assert platform_probe.installed_browser_hints() == frozenset()


def test_linux_installed_hints_uses_shutil_which(monkeypatch):
    def fake_which(name):
        return "/usr/bin/firefox" if name == "firefox" else None

    monkeypatch.setattr(platform_probe.shutil, "which", fake_which)
    result = platform_probe._linux_installed_hints()
    assert result == frozenset({"firefox"})


def test_macos_installed_hints_reads_bundle_id(tmp_path, monkeypatch):
    import plistlib
    from pathlib import Path as RealPath

    app_dir = tmp_path / "Applications"
    bundle = app_dir / "Firefox.app" / "Contents"
    bundle.mkdir(parents=True)
    with (bundle / "Info.plist").open("wb") as f:
        plistlib.dump({"CFBundleIdentifier": "org.mozilla.firefox"}, f)
    # A non-matching app must be silently skipped, not collected.
    other = app_dir / "Random.app" / "Contents"
    other.mkdir(parents=True)
    with (other / "Info.plist").open("wb") as f:
        plistlib.dump({"CFBundleIdentifier": "com.random.unrelated"}, f)

    monkeypatch.setattr(RealPath, "home", classmethod(lambda cls: tmp_path))

    result = platform_probe._macos_installed_hints()
    assert result == frozenset({"org.mozilla.firefox"})


def test_windows_installed_hints_degrades_gracefully_when_keys_absent(monkeypatch):
    # No App Paths registered for any known browser -> empty, not an error.
    fake = types.SimpleNamespace(
        HKEY_LOCAL_MACHINE=1,
        KEY_READ=0x20019,
        KEY_WOW64_64KEY=0x0100,
        KEY_WOW64_32KEY=0x0200,
        OpenKey=lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError()),
    )
    monkeypatch.setitem(sys.modules, "winreg", fake)
    assert platform_probe._windows_installed_hints() == frozenset()
