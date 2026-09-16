"""Pipfile, setup.cfg, environment.yml. PLAN.md sections 4.1, 4.3, 11 (edge cases 10, 11)."""

from __future__ import annotations

from ai_sdk_scanner.models import DependencyGroup, VersionSpecKind
from ai_sdk_scanner.parsers.python_misc import (
    parse_environment_yml,
    parse_pipfile,
    parse_setup_cfg,
)

# --- Pipfile -----------------------------------------------------------

def test_pipfile_star_is_unpinned(tmp_path):
    path = tmp_path / "Pipfile"
    path.write_text('[packages]\nopenai = "*"\n', encoding="utf-8")
    refs = parse_pipfile(path, file_path="Pipfile")
    assert refs[0].version_spec == ""
    assert refs[0].version_spec_kind == VersionSpecKind.UNPINNED


def test_pipfile_dev_packages_group(tmp_path):
    path = tmp_path / "Pipfile"
    path.write_text('[packages]\nopenai = "*"\n\n[dev-packages]\npytest = "*"\n', encoding="utf-8")
    refs = parse_pipfile(path, file_path="Pipfile")
    by_name = {r.name: r for r in refs}
    assert by_name["openai"].dependency_group == DependencyGroup.MAIN
    assert by_name["pytest"].dependency_group == DependencyGroup.DEV


def test_pipfile_table_form_version(tmp_path):
    path = tmp_path / "Pipfile"
    path.write_text('[packages]\nopenai = {version = ">=1.0"}\n', encoding="utf-8")
    refs = parse_pipfile(path, file_path="Pipfile")
    assert refs[0].version_spec == ">=1.0"


# --- setup.cfg -----------------------------------------------------------

def test_setup_cfg_install_requires(tmp_path):
    path = tmp_path / "setup.cfg"
    path.write_text(
        "[options]\ninstall_requires =\n    openai>=1.0\n    anthropic\n",
        encoding="utf-8",
    )
    refs = parse_setup_cfg(path, file_path="setup.cfg")
    names = {r.name for r in refs}
    assert names == {"openai", "anthropic"}
    assert all(r.dependency_group == DependencyGroup.MAIN for r in refs)


def test_setup_cfg_extras_require(tmp_path):
    path = tmp_path / "setup.cfg"
    path.write_text(
        "[options.extras_require]\nai =\n    openai>=1.0\n",
        encoding="utf-8",
    )
    refs = parse_setup_cfg(path, file_path="setup.cfg")
    assert refs[0].name == "openai"
    assert refs[0].dependency_group == DependencyGroup.OPTIONAL


def test_setup_cfg_missing_sections_returns_empty(tmp_path):
    path = tmp_path / "setup.cfg"
    path.write_text("[metadata]\nname = foo\n", encoding="utf-8")
    assert parse_setup_cfg(path, file_path="setup.cfg") == []


# --- environment.yml -----------------------------------------------------

def test_environment_yml_flat_conda_deps(tmp_path):
    path = tmp_path / "environment.yml"
    path.write_text(
        "name: myenv\ndependencies:\n  - python=3.11\n  - pytorch=2.1\n",
        encoding="utf-8",
    )
    refs = parse_environment_yml(path, file_path="environment.yml")
    by_name = {r.name: r for r in refs}
    assert by_name["pytorch"].version_spec == "2.1"
    assert by_name["pytorch"].version_spec_kind == VersionSpecKind.PINNED  # edge case 11


def test_environment_yml_bare_conda_entry_is_unpinned(tmp_path):
    path = tmp_path / "environment.yml"
    path.write_text("dependencies:\n  - numpy\n", encoding="utf-8")
    refs = parse_environment_yml(path, file_path="environment.yml")
    assert refs[0].version_spec_kind == VersionSpecKind.UNPINNED


def test_environment_yml_nested_pip_block(tmp_path):
    path = tmp_path / "environment.yml"
    path.write_text(
        "dependencies:\n"
        "  - python=3.11\n"
        "  - pip:\n"
        "    - openai>=1.0\n"
        "    - anthropic\n",
        encoding="utf-8",
    )
    refs = parse_environment_yml(path, file_path="environment.yml")
    by_name = {r.name: r for r in refs}
    assert "openai" in by_name
    assert by_name["openai"].version_spec == ">=1.0"
    assert "anthropic" in by_name
    assert "python" in by_name  # the conda python pin is still emitted; catalog just won't match it


def test_environment_yml_pip_block_ends_at_next_conda_entry(tmp_path):
    path = tmp_path / "environment.yml"
    path.write_text(
        "dependencies:\n"
        "  - pip:\n"
        "    - openai\n"
        "  - pytorch=2.1\n",
        encoding="utf-8",
    )
    refs = parse_environment_yml(path, file_path="environment.yml")
    by_name = {r.name: r for r in refs}
    assert by_name["pytorch"].version_spec_kind == VersionSpecKind.PINNED
    assert by_name["openai"].version_spec_kind == VersionSpecKind.UNPINNED


def test_environment_yml_no_dependencies_key_returns_empty(tmp_path):
    path = tmp_path / "environment.yml"
    path.write_text("name: myenv\nchannels:\n  - conda-forge\n", encoding="utf-8")
    assert parse_environment_yml(path, file_path="environment.yml") == []
