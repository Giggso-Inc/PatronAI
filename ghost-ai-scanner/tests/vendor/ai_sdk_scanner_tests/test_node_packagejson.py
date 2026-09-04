"""package.json. PLAN.md sections 4.1, 11 (edge case 6)."""

from __future__ import annotations

import json

from ai_sdk_scanner.models import DependencyGroup, VersionSpecKind
from ai_sdk_scanner.parsers.node_packagejson import parse


def _write_and_parse(tmp_path, data):
    path = tmp_path / "package.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return parse(path, file_path="package.json")


def test_all_four_dependency_sections(tmp_path):
    refs = _write_and_parse(tmp_path, {
        "dependencies": {"openai": "^4.20.0"},
        "devDependencies": {"jest": "^29.0.0"},
        "peerDependencies": {"react": "^18.0.0"},
        "optionalDependencies": {"fsevents": "^2.0.0"},
    })
    by_name = {r.name: r for r in refs}
    assert by_name["openai"].dependency_group == DependencyGroup.MAIN
    assert by_name["jest"].dependency_group == DependencyGroup.DEV
    assert by_name["react"].dependency_group == DependencyGroup.PEER
    assert by_name["fsevents"].dependency_group == DependencyGroup.OPTIONAL


def test_same_library_in_two_groups_produces_two_rows(tmp_path):
    # PLAN.md edge case 6.
    refs = _write_and_parse(tmp_path, {
        "dependencies": {"openai": "^4.20.0"},
        "devDependencies": {"openai": "^4.20.0"},
    })
    assert len(refs) == 2
    groups = {r.dependency_group for r in refs}
    assert groups == {DependencyGroup.MAIN, DependencyGroup.DEV}


def test_caret_version_is_a_range(tmp_path):
    refs = _write_and_parse(tmp_path, {"dependencies": {"openai": "^4.20.0"}})
    assert refs[0].version_spec_kind == VersionSpecKind.RANGE
    assert refs[0].version_spec == "^4.20.0"


def test_scoped_package_name_preserved(tmp_path):
    refs = _write_and_parse(tmp_path, {"dependencies": {"@anthropic-ai/sdk": "^0.20.0"}})
    assert refs[0].name == "@anthropic-ai/sdk"


def test_malformed_json_returns_empty(tmp_path):
    path = tmp_path / "package.json"
    path.write_text("{not valid json", encoding="utf-8")
    assert parse(path, file_path="package.json") == []


def test_non_string_version_value_is_skipped(tmp_path):
    refs = _write_and_parse(tmp_path, {"dependencies": {"openai": 123}})
    assert refs == []
