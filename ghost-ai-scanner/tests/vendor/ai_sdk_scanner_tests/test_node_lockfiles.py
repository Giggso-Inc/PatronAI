"""package-lock.json, yarn.lock, pnpm-lock.yaml. PLAN.md sections 4.1, 6.2, 3.4."""

from __future__ import annotations

import json

from ai_sdk_scanner.models import DependencyGroup, VersionSource, VersionSpecKind
from ai_sdk_scanner.parsers.node_lockfiles import (
    parse_package_lock_json,
    parse_pnpm_lock,
    parse_yarn_lock,
)

# --- package-lock.json v2/v3 ("packages" map) -------------------------------

def test_npm_v2_direct_dependency(tmp_path):
    data = {
        "packages": {
            "": {"name": "root"},
            "node_modules/openai": {"version": "4.20.1", "dev": False},
        }
    }
    path = tmp_path / "package-lock.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    refs = parse_package_lock_json(path, file_path="package-lock.json", include_transitive=False)
    assert len(refs) == 1
    assert refs[0].name == "openai"
    assert refs[0].version_spec == "4.20.1"
    assert refs[0].version_spec_kind == VersionSpecKind.RESOLVED
    assert refs[0].version_source == VersionSource.RESOLVED
    assert refs[0].is_direct is True


def test_npm_v2_transitive_excluded_by_default(tmp_path):
    data = {
        "packages": {
            "": {},
            "node_modules/openai": {"version": "4.20.1"},
            "node_modules/openai/node_modules/agentkeepalive": {"version": "4.5.0"},
        }
    }
    path = tmp_path / "package-lock.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    refs = parse_package_lock_json(path, file_path="package-lock.json", include_transitive=False)
    assert [r.name for r in refs] == ["openai"]

    refs_with_transitive = parse_package_lock_json(
        path, file_path="package-lock.json", include_transitive=True
    )
    names = {r.name for r in refs_with_transitive}
    assert names == {"openai", "agentkeepalive"}
    by_name = {r.name: r for r in refs_with_transitive}
    assert by_name["agentkeepalive"].is_direct is False


def test_npm_v2_dev_flag_maps_to_dev_group(tmp_path):
    data = {"packages": {"": {}, "node_modules/jest": {"version": "29.0.0", "dev": True}}}
    path = tmp_path / "package-lock.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    refs = parse_package_lock_json(path, file_path="package-lock.json", include_transitive=False)
    assert refs[0].dependency_group == DependencyGroup.DEV


# --- package-lock.json v1 (nested "dependencies" tree) ----------------------

def test_npm_v1_nested_tree_direct_vs_transitive(tmp_path):
    data = {
        "dependencies": {
            "openai": {
                "version": "4.20.1",
                "dependencies": {"agentkeepalive": {"version": "4.5.0"}},
            }
        }
    }
    path = tmp_path / "package-lock.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    refs = parse_package_lock_json(path, file_path="package-lock.json", include_transitive=False)
    assert [r.name for r in refs] == ["openai"]

    refs_transitive = parse_package_lock_json(
        path, file_path="package-lock.json", include_transitive=True
    )
    names = {r.name: r.is_direct for r in refs_transitive}
    assert names == {"openai": True, "agentkeepalive": False}


# --- yarn.lock ---------------------------------------------------------------

_YARN_LOCK_SAMPLE = '''
# yarn lockfile v1


"@anthropic-ai/sdk@^0.20.0":
  version "0.20.1"
  resolved "https://registry.yarnpkg.com/@anthropic-ai/sdk/-/sdk-0.20.1.tgz"
  dependencies:
    "@types/node" "^18.0.0"

"openai@^4.20.0", "openai@^4.21.0":
  version "4.21.0"
  resolved "https://registry.yarnpkg.com/openai/-/openai-4.21.0.tgz"
'''


def test_yarn_lock_gated_behind_include_transitive(tmp_path):
    path = tmp_path / "yarn.lock"
    path.write_text(_YARN_LOCK_SAMPLE, encoding="utf-8")
    assert parse_yarn_lock(path, file_path="yarn.lock", include_transitive=False) == []


def test_yarn_lock_scoped_package_name(tmp_path):
    path = tmp_path / "yarn.lock"
    path.write_text(_YARN_LOCK_SAMPLE, encoding="utf-8")
    refs = parse_yarn_lock(path, file_path="yarn.lock", include_transitive=True)
    by_name = {r.name: r for r in refs}
    assert by_name["@anthropic-ai/sdk"].version_spec == "0.20.1"
    assert by_name["@anthropic-ai/sdk"].is_direct is False


def test_yarn_lock_multiple_specs_one_version(tmp_path):
    path = tmp_path / "yarn.lock"
    path.write_text(_YARN_LOCK_SAMPLE, encoding="utf-8")
    refs = parse_yarn_lock(path, file_path="yarn.lock", include_transitive=True)
    openai_refs = [r for r in refs if r.name == "openai"]
    assert len(openai_refs) == 1
    assert openai_refs[0].version_spec == "4.21.0"


# --- pnpm-lock.yaml -----------------------------------------------------------

_PNPM_LOCK_SAMPLE = """lockfileVersion: '9.0'

dependencies:
  openai:
    version: 4.20.1
  '@anthropic-ai/sdk':
    version: 0.20.1(zod@3.22.0)

devDependencies:
  jest:
    version: 29.0.0

packages:
  /openai@4.20.1:
    resolution: {integrity: sha512-abc}
"""


def test_pnpm_lock_top_level_dependencies(tmp_path):
    path = tmp_path / "pnpm-lock.yaml"
    path.write_text(_PNPM_LOCK_SAMPLE, encoding="utf-8")
    refs = parse_pnpm_lock(path, file_path="pnpm-lock.yaml", include_transitive=False)
    by_name = {r.name: r for r in refs}
    assert by_name["openai"].version_spec == "4.20.1"
    assert by_name["openai"].is_direct is True
    assert by_name["jest"].dependency_group == DependencyGroup.DEV


def test_pnpm_lock_ignores_nested_packages_graph(tmp_path):
    path = tmp_path / "pnpm-lock.yaml"
    path.write_text(_PNPM_LOCK_SAMPLE, encoding="utf-8")
    refs = parse_pnpm_lock(path, file_path="pnpm-lock.yaml", include_transitive=True)
    # The "packages:" section's "/openai@4.20.1" entry must not appear as
    # its own row -- only the top-level dependencies: map is read.
    names = [r.name for r in refs]
    assert "openai" in names
    assert names.count("openai") == 1
