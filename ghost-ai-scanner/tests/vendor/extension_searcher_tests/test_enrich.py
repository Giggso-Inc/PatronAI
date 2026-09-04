"""PLAN.md section 12: regression coverage for the two documented silent-bug
traps — the Chromium/Unix epoch mismatch, and unresolved __MSG_* names."""

from __future__ import annotations

import json

from extension_searcher.enrich import (
    chromium_time_to_iso,
    gecko_time_to_iso,
    resolve_localized_name,
)


def test_chromium_epoch_is_not_unix_epoch():
    # A known value: 13205187002131396 microseconds since 1601-01-01 UTC.
    result = chromium_time_to_iso("13205187002131396")
    assert result is not None
    assert result.startswith("2019-")  # NOT 1970/1969, which a Unix-epoch bug would give
    assert not result.startswith("1970")


def test_chromium_epoch_none_and_garbage():
    assert chromium_time_to_iso(None) is None
    assert chromium_time_to_iso("not-a-number") is None
    assert chromium_time_to_iso(0) is None


def test_gecko_epoch_is_unix_millis():
    # 1700000000000 ms -> 2023-11-14T22:13:20+00:00
    result = gecko_time_to_iso(1700000000000)
    assert result is not None
    assert result.startswith("2023-11-14")


def test_gecko_epoch_none_and_garbage():
    assert gecko_time_to_iso(None) is None
    assert gecko_time_to_iso("garbage") is None


def test_resolve_localized_name_passthrough_when_not_msg():
    name, warnings = resolve_localized_name("Plain Name", None, None)  # type: ignore[arg-type]
    assert name == "Plain Name"
    assert warnings == ()


def test_resolve_localized_name_resolves_default_locale(tmp_path):
    version_dir = tmp_path / "1.0_0"
    locales_dir = version_dir / "_locales" / "en_US"
    locales_dir.mkdir(parents=True)
    (locales_dir / "messages.json").write_text(
        json.dumps({"extName": {"message": "Resolved Name"}}), encoding="utf-8"
    )

    name, warnings = resolve_localized_name("__MSG_extName__", version_dir, "en_US")
    assert name == "Resolved Name"
    assert warnings == ()


def test_resolve_localized_name_falls_back_to_en_us(tmp_path):
    version_dir = tmp_path / "1.0_0"
    locales_dir = version_dir / "_locales" / "en_US"
    locales_dir.mkdir(parents=True)
    (locales_dir / "messages.json").write_text(
        json.dumps({"extName": {"message": "Fallback Name"}}), encoding="utf-8"
    )

    # default_locale points somewhere that doesn't exist; en_US fallback should still work.
    name, warnings = resolve_localized_name("__MSG_extName__", version_dir, "fr")
    assert name == "Fallback Name"
    assert warnings == ()


def test_resolve_localized_name_unresolvable_keeps_literal_and_warns(tmp_path):
    version_dir = tmp_path / "1.0_0"
    version_dir.mkdir(parents=True)

    name, warnings = resolve_localized_name("__MSG_missing__", version_dir, None)
    assert name == "__MSG_missing__"
    assert warnings == ("locale_unresolved",)
