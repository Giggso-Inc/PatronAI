"""composer.json. No real PHP project exists on this machine — verified
only against synthetic fixtures."""

from __future__ import annotations

import json

from ai_sdk_scanner.models import DependencyGroup, VersionSpecKind
from ai_sdk_scanner.parsers.php_composer import parse


def _write_and_parse(tmp_path, data):
    path = tmp_path / "composer.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return parse(path, file_path="composer.json")


def test_require_and_require_dev_groups(tmp_path):
    refs = _write_and_parse(tmp_path, {
        "require": {"openai-php/client": "^0.10.0"},
        "require-dev": {"phpunit/phpunit": "^10.0"},
    })
    by_name = {r.name: r for r in refs}
    assert by_name["openai-php/client"].dependency_group == DependencyGroup.MAIN
    assert by_name["phpunit/phpunit"].dependency_group == DependencyGroup.DEV


def test_platform_packages_are_excluded(tmp_path):
    refs = _write_and_parse(tmp_path, {
        "require": {
            "php": ">=8.1",
            "ext-json": "*",
            "ext-mbstring": "*",
            "lib-curl": "*",
            "openai-php/client": "^0.10.0",
        },
    })
    names = {r.name for r in refs}
    assert names == {"openai-php/client"}


def test_bare_version_is_exact_no_implicit_caret(tmp_path):
    # Composer convention (like Maven): bare version has no implicit caret,
    # unlike npm/Cargo/Poetry.
    refs = _write_and_parse(tmp_path, {"require": {"vendor/pkg": "1.2.3"}})
    assert refs[0].version_spec_kind == VersionSpecKind.PINNED


def test_caret_is_a_range(tmp_path):
    refs = _write_and_parse(tmp_path, {"require": {"vendor/pkg": "^1.2.3"}})
    assert refs[0].version_spec_kind == VersionSpecKind.RANGE


def test_star_is_unpinned(tmp_path):
    refs = _write_and_parse(tmp_path, {"require": {"vendor/pkg": "*"}})
    assert refs[0].version_spec_kind == VersionSpecKind.UNPINNED


def test_malformed_json_returns_empty(tmp_path):
    path = tmp_path / "composer.json"
    path.write_text("{not valid json", encoding="utf-8")
    assert parse(path, file_path="composer.json") == []


def test_line_number_is_recorded(tmp_path):
    refs = _write_and_parse(tmp_path, {"require": {"vendor/pkg": "1.0.0"}})
    assert refs[0].line_number is not None
