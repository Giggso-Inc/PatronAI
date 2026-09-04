"""Internet Explorer parser — Windows only. PLAN.md sections 5.3, 6.9.

Everything comes from the registry, not the filesystem. Every record is
`confidence=partial` with empty `permissions` — this is a platform limit,
not a parsing gap (PLAN.md section 5.3). On Windows 11, IE is removed and
this normally returns zero records; that is a valid, informative answer,
not a failure (PLAN.md section 6.9's "expectation setting" note).
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from os import path as os_path
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
from extension_searcher.platform_probe import is_windows

logger = logging.getLogger(__name__)

_BHO_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
_TOOLBAR_KEY = r"SOFTWARE\Microsoft\Internet Explorer\Toolbar"
_EXTENSIONS_KEY = r"SOFTWARE\Microsoft\Internet Explorer\Extensions"


def scan() -> tuple[BrowserHit, list[ExtensionRecord], list[ScanError]]:
    """Enumerate BHOs, toolbars, and IE Extensions. PLAN.md section 6.9."""
    if not is_windows():
        raise UnsupportedPlatformError("Internet Explorer parser requires Windows")

    import winreg

    roots_checked: list[str] = []
    errors: list[ScanError] = []
    clsids: dict[str, str] = {}  # clsid -> which key family found it

    key_families = (
        (winreg.HKEY_LOCAL_MACHINE, _BHO_KEY, "bho"),
        (winreg.HKEY_LOCAL_MACHINE, _TOOLBAR_KEY, "toolbar"),
        (winreg.HKEY_CURRENT_USER, _TOOLBAR_KEY, "toolbar"),
        (winreg.HKEY_LOCAL_MACHINE, _EXTENSIONS_KEY, "extension"),
    )

    for hive, subkey, family in key_families:
        hive_name = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
        for view_name, access in (
            ("64", winreg.KEY_WOW64_64KEY),
            ("32", winreg.KEY_WOW64_32KEY),
        ):
            root_label = f"{hive_name}\\{subkey} ({view_name}-bit)"
            roots_checked.append(root_label)
            try:
                found = list(_enum_subkeys(hive, subkey, winreg.KEY_READ | access))
            except FileNotFoundError:
                continue  # Absent is the normal case, not an error (edge case 20).
            except OSError as exc:
                errors.append(ScanError(root_label, "access_denied", str(exc)))
                continue
            for clsid in found:
                clsids.setdefault(clsid, family)

    records: list[ExtensionRecord] = [
        r for clsid, family in clsids.items() if (r := _build_record(clsid, family)) is not None
    ]

    hit = BrowserHit(
        "Internet Explorer",
        Engine.TRIDENT,
        found=bool(clsids),
        roots_checked=tuple(roots_checked),
        profiles=(),
        unverified=False,
    )
    return hit, records, errors


@contextmanager
def _open_key(hive: int, subkey: str, access: int) -> Iterator[Any]:
    import winreg

    key = winreg.OpenKey(hive, subkey, 0, access)
    try:
        yield key
    finally:
        winreg.CloseKey(key)


def _enum_subkeys(hive: int, subkey: str, access: int) -> list[str]:
    import winreg

    names: list[str] = []
    with _open_key(hive, subkey, access) as key:
        index = 0
        while True:
            try:
                names.append(winreg.EnumKey(key, index))
            except OSError:
                break
            index += 1
    return names


def _read_default_value(hive: int, subkey: str) -> str | None:
    import winreg

    try:
        with _open_key(hive, subkey, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, "")
            return str(value) if value else None
    except (FileNotFoundError, OSError):
        return None


def _is_disabled(clsid: str) -> bool:
    import winreg

    subkey = rf"SOFTWARE\Microsoft\Windows\CurrentVersion\Ext\Settings\{clsid}"
    try:
        with _open_key(winreg.HKEY_CURRENT_USER, subkey, winreg.KEY_READ) as key:
            flags, _ = winreg.QueryValueEx(key, "Flags")
            return int(flags) == 1
    except (FileNotFoundError, OSError, ValueError):
        return False  # Absence of the key means enabled (PLAN.md section 6.9).


def _build_record(clsid: str, family: str) -> ExtensionRecord | None:
    import winreg

    name = _read_default_value(winreg.HKEY_CLASSES_ROOT, rf"CLSID\{clsid}")
    dll_path_raw = _read_default_value(winreg.HKEY_CLASSES_ROOT, rf"CLSID\{clsid}\InprocServer32")
    dll_path = os_path.expandvars(dll_path_raw) if dll_path_raw else "unknown"

    if not name:
        # Fall back to the DLL filename stem (PLAN.md section 6.9, CLSID resolution step 3).
        name = os_path.splitext(os_path.basename(dll_path))[0] if dll_path != "unknown" else clsid

    enabled = not _is_disabled(clsid)

    return ExtensionRecord(
        extension_id=clsid,
        name=name,
        version="unknown",
        description=None,
        browser="Internet Explorer",
        browser_channel=None,
        engine=Engine.TRIDENT,
        profile_dir="(machine)",
        profile_name=None,
        install_path=dll_path,
        enabled=enabled,
        disabled_reason=None,
        state_source="registry",
        install_origin=InstallOrigin.UNKNOWN,
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
        source_files=(f"CLSID\\{clsid}",),
        confidence=Confidence.PARTIAL,
        warnings=(f"category:{family}",),
    )
