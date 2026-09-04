"""Cargo.toml. No real Rust project exists on this machine — verified
only against synthetic fixtures."""

from __future__ import annotations

from ai_sdk_scanner.models import DependencyGroup, VersionSpecKind
from ai_sdk_scanner.parsers.rust_cargo import parse


def _write_and_parse(tmp_path, content):
    path = tmp_path / "Cargo.toml"
    path.write_text(content, encoding="utf-8")
    return parse(path, file_path="Cargo.toml")


def test_string_form_bare_version_is_a_caret_range(tmp_path):
    # Cargo convention: an operator-less version is a caret requirement by
    # default, the same as Poetry -- NOT an exact pin.
    refs = _write_and_parse(tmp_path, '[dependencies]\nasync-openai = "0.20.0"\n')
    assert refs[0].version_spec_kind == VersionSpecKind.RANGE


def test_explicit_equals_is_pinned(tmp_path):
    refs = _write_and_parse(tmp_path, '[dependencies]\nasync-openai = "=0.20.0"\n')
    assert refs[0].version_spec_kind == VersionSpecKind.PINNED


def test_dev_dependencies_group(tmp_path):
    refs = _write_and_parse(tmp_path, '[dev-dependencies]\ntokio-test = "0.4"\n')
    assert refs[0].dependency_group == DependencyGroup.DEV


def test_build_dependencies_group(tmp_path):
    refs = _write_and_parse(tmp_path, '[build-dependencies]\ncc = "1.0"\n')
    assert refs[0].dependency_group == DependencyGroup.DEV


def test_table_form_with_features_and_optional(tmp_path):
    content = (
        '[dependencies]\n'
        'async-openai = { version = "0.20.0", features = ["stream"], optional = true }\n'
    )
    refs = _write_and_parse(tmp_path, content)
    r = refs[0]
    assert r.version_spec == "0.20.0"
    assert r.is_optional is True
    assert r.dependency_group == DependencyGroup.OPTIONAL


def test_git_dependency_with_branch(tmp_path):
    refs = _write_and_parse(
        tmp_path,
        '[dependencies]\nmy-fork = { git = "https://github.com/me/fork", branch = "main" }\n',
    )
    r = refs[0]
    assert r.vcs_url == "https://github.com/me/fork"
    assert r.vcs_ref == "main"


def test_path_dependency(tmp_path):
    refs = _write_and_parse(tmp_path, '[dependencies]\nlocal-lib = { path = "../local-lib" }\n')
    assert refs[0].local_path == "../local-lib"


def test_workspace_true_without_version_is_unpinned(tmp_path):
    refs = _write_and_parse(tmp_path, '[dependencies]\nshared-dep = { workspace = true }\n')
    assert refs[0].version_spec == ""
    assert refs[0].version_spec_kind == VersionSpecKind.UNPINNED


def test_target_specific_dependencies_are_parsed(tmp_path):
    refs = _write_and_parse(
        tmp_path,
        '[target.\'cfg(unix)\'.dependencies]\nlibc = "0.2"\n',
    )
    assert refs[0].name == "libc"


def test_malformed_toml_returns_empty(tmp_path):
    path = tmp_path / "Cargo.toml"
    path.write_text("[dependencies\nbroken", encoding="utf-8")
    assert parse(path, file_path="Cargo.toml") == []
