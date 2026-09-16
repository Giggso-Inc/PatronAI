"""Internet Explorer parser, tested against an in-memory fake registry
(PLAN.md section 12: "winreg accessed through a thin wrapper... tests
replace with an in-memory fake key tree" — no real registry reads/writes).
"""

from __future__ import annotations

import sys
import types

import pytest

from extension_searcher.parsers import trident


class FakeWinReg:
    """Minimal winreg surface: HKEY constants, OpenKey/CloseKey/EnumKey/
    QueryValueEx, backed by a plain nested-dict tree keyed by
    (hive, subkey.lower())."""

    HKEY_LOCAL_MACHINE = 1
    HKEY_CURRENT_USER = 2
    HKEY_CLASSES_ROOT = 3
    KEY_READ = 0x20019
    KEY_WOW64_64KEY = 0x0100
    KEY_WOW64_32KEY = 0x0200

    def __init__(self):
        # (hive, subkey_lower) -> {"default", "subkeys", "values"} - see add_key below.
        self.tree: dict[tuple[int, str], dict] = {}

    def add_key(self, hive, subkey, default=None, subkeys=(), values=None):
        self.tree[(hive, subkey.lower())] = {
            "default": default,
            "subkeys": list(subkeys),
            "values": values or {},
        }

    def OpenKey(self, hive, subkey, reserved=0, access=0):
        entry = self.tree.get((hive, subkey.lower()))
        if entry is None:
            raise FileNotFoundError(subkey)
        return (hive, subkey.lower())

    def CloseKey(self, key):
        pass

    def EnumKey(self, key, index):
        entry = self.tree[key]
        if index >= len(entry["subkeys"]):
            raise OSError("no more items")
        return entry["subkeys"][index]

    def QueryValueEx(self, key, name):
        entry = self.tree[key]
        if name == "":
            if entry["default"] is None:
                raise FileNotFoundError("no default value")
            return entry["default"], 1
        if name not in entry["values"]:
            raise FileNotFoundError(name)
        return entry["values"][name], 4


@pytest.fixture
def fake_winreg(monkeypatch):
    fake = FakeWinReg()
    module = types.SimpleNamespace(**{
        k: v for k, v in vars(FakeWinReg).items() if not k.startswith("_")
    })
    # Bind instance methods so `self` is the fake registry, not the class.
    for name in ("OpenKey", "CloseKey", "EnumKey", "QueryValueEx"):
        setattr(module, name, getattr(fake, name))
    monkeypatch.setitem(sys.modules, "winreg", module)
    monkeypatch.setattr(trident, "is_windows", lambda: True)
    return fake


def test_scan_finds_a_bho_with_resolved_name(fake_winreg):
    clsid = "{11111111-1111-1111-1111-111111111111}"
    bho_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
    fake_winreg.add_key(fake_winreg.HKEY_LOCAL_MACHINE, bho_key, subkeys=[clsid])
    fake_winreg.add_key(
        fake_winreg.HKEY_CLASSES_ROOT, rf"CLSID\{clsid}", default="My BHO"
    )
    fake_winreg.add_key(
        fake_winreg.HKEY_CLASSES_ROOT,
        rf"CLSID\{clsid}\InprocServer32",
        default=r"C:\Program Files\Vendor\bho.dll",
    )

    hit, records, errors = trident.scan()

    assert hit.found is True
    assert errors == []
    assert len(records) == 1
    r = records[0]
    assert r.name == "My BHO"
    assert r.extension_id == clsid
    assert r.install_path == r"C:\Program Files\Vendor\bho.dll"
    assert r.enabled is True  # no Ext\Settings\{clsid} entry -> enabled by default
    assert r.confidence.value == "partial"
    assert r.permissions == ()


def test_scan_respects_disabled_flag(fake_winreg):
    clsid = "{22222222-2222-2222-2222-222222222222}"
    bho_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
    fake_winreg.add_key(fake_winreg.HKEY_LOCAL_MACHINE, bho_key, subkeys=[clsid])
    fake_winreg.add_key(fake_winreg.HKEY_CLASSES_ROOT, rf"CLSID\{clsid}", default="Disabled BHO")
    settings_key = rf"SOFTWARE\Microsoft\Windows\CurrentVersion\Ext\Settings\{clsid}"
    fake_winreg.add_key(
        fake_winreg.HKEY_CURRENT_USER, settings_key, values={"Flags": 1}
    )

    hit, records, errors = trident.scan()

    assert len(records) == 1
    assert records[0].enabled is False


def test_scan_falls_back_to_dll_stem_when_no_friendly_name(fake_winreg):
    clsid = "{33333333-3333-3333-3333-333333333333}"
    bho_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
    fake_winreg.add_key(fake_winreg.HKEY_LOCAL_MACHINE, bho_key, subkeys=[clsid])
    fake_winreg.add_key(
        fake_winreg.HKEY_CLASSES_ROOT,
        rf"CLSID\{clsid}\InprocServer32",
        default=r"C:\Somewhere\mystery_helper.dll",
    )

    hit, records, errors = trident.scan()

    assert len(records) == 1
    assert records[0].name == "mystery_helper"


def test_scan_with_nothing_registered_returns_empty_not_found(fake_winreg):
    hit, records, errors = trident.scan()

    assert hit.found is False
    assert records == []
    assert errors == []
    assert len(hit.roots_checked) > 0  # absence still visible (PLAN.md section 14)
