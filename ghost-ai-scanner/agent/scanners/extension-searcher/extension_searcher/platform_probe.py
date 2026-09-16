"""Per-OS root resolution and installed-browser detection.

PLAN.md section 5.4: this is how the tool tells "browser present, zero
extensions" apart from "browser absent" — the distinction that makes a
clean report trustworthy rather than merely quiet.
"""

from __future__ import annotations

import logging
import os
import shutil
import sys
from pathlib import Path

from extension_searcher.registry import RootKind

logger = logging.getLogger(__name__)

_WINDOWS_APP_PATH_EXES = (
    "chrome.exe", "msedge.exe", "brave.exe", "firefox.exe",
    "opera.exe", "vivaldi.exe", "yandex.exe",
)

_MACOS_KNOWN_BUNDLE_IDS = (
    "com.google.Chrome", "org.mozilla.firefox", "com.brave.Browser",
    "com.microsoft.edgemac", "com.operasoftware.Opera", "com.vivaldi.Vivaldi",
    "com.apple.Safari", "org.mozilla.firefoxdeveloperedition",
)

_LINUX_KNOWN_BINARIES = (
    "google-chrome", "google-chrome-stable", "firefox", "brave-browser",
    "microsoft-edge", "microsoft-edge-stable", "opera", "vivaldi",
    "chromium", "chromium-browser",
)


def current_os() -> str:
    """One of 'windows', 'macos', 'linux', or 'other'."""
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    if sys.platform.startswith("linux"):
        return "linux"
    return "other"


def is_windows() -> bool:
    return current_os() == "windows"


def is_macos() -> bool:
    return current_os() == "macos"


def is_linux() -> bool:
    return current_os() == "linux"


def resolve_root(root_kind: str) -> Path | None:
    """Resolve a `RootKind` to an actual directory for the current OS.

    Returns None when the root kind does not apply to this OS (e.g. asking
    for WIN_LOCALAPPDATA while running on Linux) — callers treat None as
    "this candidate path does not exist here", not as an error.
    """
    os_name = current_os()

    if root_kind == RootKind.WIN_LOCALAPPDATA:
        if os_name != "windows":
            return None
        base = os.environ.get("LOCALAPPDATA")
        return Path(base) if base else None

    if root_kind == RootKind.WIN_APPDATA:
        if os_name != "windows":
            return None
        base = os.environ.get("APPDATA")
        return Path(base) if base else None

    if root_kind == RootKind.MAC_APP_SUPPORT:
        if os_name != "macos":
            return None
        return Path.home() / "Library" / "Application Support"

    if root_kind == RootKind.LINUX_CONFIG:
        if os_name != "linux":
            return None
        base = os.environ.get("XDG_CONFIG_HOME")
        return Path(base) if base else Path.home() / ".config"

    if root_kind == RootKind.HOME:
        return Path.home()

    logger.warning("Unknown root kind %r", root_kind)
    return None


def installed_browser_hints() -> frozenset[str]:
    """Best-effort set of lowercase hints for browsers installed on this host.

    Used only to annotate "present but empty" vs "absent" — never to gate
    whether a profile directory is scanned. Failures here are swallowed and
    logged; they must never abort a scan (PLAN.md section 11, item 7).
    """
    try:
        if is_windows():
            return _windows_installed_hints()
        if is_macos():
            return _macos_installed_hints()
        if is_linux():
            return _linux_installed_hints()
    except OSError:
        logger.warning("Installed-browser probe failed", exc_info=True)
    return frozenset()


def _windows_installed_hints() -> frozenset[str]:
    import winreg

    hints: set[str] = set()
    key_paths = (
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths"),
    )
    for hive, base in key_paths:
        for access in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
            try:
                with winreg.OpenKey(hive, base, 0, winreg.KEY_READ | access) as key:
                    for exe in _WINDOWS_APP_PATH_EXES:
                        try:
                            with winreg.OpenKey(key, exe):
                                hints.add(exe.removesuffix(".exe"))
                        except FileNotFoundError:
                            continue
            except FileNotFoundError:
                continue
    return frozenset(hints)


def _macos_installed_hints() -> frozenset[str]:
    import plistlib

    hints: set[str] = set()
    app_dirs = [Path("/Applications"), Path.home() / "Applications"]
    for app_dir in app_dirs:
        if not app_dir.is_dir():
            continue
        for entry in app_dir.iterdir():
            if entry.suffix != ".app":
                continue
            info_plist = entry / "Contents" / "Info.plist"
            if not info_plist.is_file():
                continue
            try:
                with info_plist.open("rb") as f:
                    data = plistlib.load(f)
            except (OSError, ValueError):
                continue
            bundle_id = data.get("CFBundleIdentifier")
            if bundle_id in _MACOS_KNOWN_BUNDLE_IDS:
                hints.add(bundle_id)
    return frozenset(hints)


def _linux_installed_hints() -> frozenset[str]:
    return frozenset(
        name for name in _LINUX_KNOWN_BINARIES if shutil.which(name)
    )
