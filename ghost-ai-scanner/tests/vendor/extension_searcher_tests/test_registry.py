"""Sanity checks on the path table itself. PLAN.md section 5: this is a
declarative data table — these tests catch structural mistakes (a browser
with no rows for any OS, a duplicate name, a malformed RootKind) rather
than testing any real filesystem path."""

from __future__ import annotations

from extension_searcher.models import Engine
from extension_searcher.registry import (
    ALL_BROWSERS,
    CHROMIUM_BROWSERS,
    GECKO_BROWSERS,
    RootKind,
)

_VALID_ROOT_KINDS = {
    RootKind.WIN_LOCALAPPDATA,
    RootKind.WIN_APPDATA,
    RootKind.MAC_APP_SUPPORT,
    RootKind.HOME,
    RootKind.LINUX_CONFIG,
}


def test_all_browsers_is_the_union():
    assert set(ALL_BROWSERS) == set(CHROMIUM_BROWSERS) | set(GECKO_BROWSERS)


def test_no_duplicate_browser_names():
    names = [spec.name for spec in ALL_BROWSERS]
    assert len(names) == len(set(names)), "duplicate browser name in the registry"


def test_every_spec_has_at_least_one_os_row():
    for spec in ALL_BROWSERS:
        assert spec.windows or spec.macos or spec.linux, (
            f"{spec.name} has no path-table rows for any OS"
        )


def test_every_path_entry_uses_a_known_root_kind():
    for spec in ALL_BROWSERS:
        for entries in (spec.windows, spec.macos, spec.linux):
            for entry in entries:
                assert entry.root in _VALID_ROOT_KINDS, (
                    f"{spec.name} has an unrecognized root kind: {entry.root}"
                )


def test_chromium_specs_are_all_chromium_engine():
    assert all(spec.engine == Engine.CHROMIUM for spec in CHROMIUM_BROWSERS)


def test_gecko_specs_are_all_gecko_engine():
    assert all(spec.engine == Engine.GECKO for spec in GECKO_BROWSERS)


def test_macos_rows_default_to_unverified():
    # PLAN.md section 15.1: no macOS host has confirmed these paths.
    for spec in ALL_BROWSERS:
        if spec.macos:
            assert spec.macos_unverified is True, (
                f"{spec.name} claims verified macOS paths with no host to back it"
            )
