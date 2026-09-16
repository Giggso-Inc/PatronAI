"""pyproject.toml: PEP 621, Poetry, PDM, uv. PLAN.md sections 4.1, 11 (edge cases 8, 9)."""

from __future__ import annotations

from ai_sdk_scanner.models import DependencyGroup, VersionSpecKind
from ai_sdk_scanner.parsers.python_pyproject import parse


def _write_and_parse(tmp_path, content):
    path = tmp_path / "pyproject.toml"
    path.write_text(content, encoding="utf-8")
    return parse(path, file_path="pyproject.toml")


def test_pep621_main_and_optional(tmp_path):
    refs = _write_and_parse(tmp_path, """
[project]
dependencies = ["openai>=1.0", "anthropic"]

[project.optional-dependencies]
dev = ["pytest"]
""")
    by_name = {r.name: r for r in refs}
    assert by_name["openai"].dependency_group == DependencyGroup.MAIN
    assert by_name["openai"].version_spec == ">=1.0"
    assert by_name["pytest"].dependency_group == DependencyGroup.OPTIONAL


def test_pep735_dependency_groups(tmp_path):
    refs = _write_and_parse(tmp_path, """
[dependency-groups]
dev = ["pytest>=8.0"]
""")
    assert refs[0].name == "pytest"
    assert refs[0].dependency_group == DependencyGroup.DEV


def test_poetry_string_form(tmp_path):
    refs = _write_and_parse(tmp_path, """
[tool.poetry.dependencies]
python = "^3.11"
openai = "^1.30.0"
""")
    names = {r.name for r in refs}
    assert names == {"openai"}  # "python" excluded — PLAN.md edge case 8


def test_poetry_table_form_with_version_key(tmp_path):
    refs = _write_and_parse(tmp_path, """
[tool.poetry.dependencies]
openai = {version = "^1.30.0", optional = true}
""")
    assert refs[0].name == "openai"
    assert refs[0].version_spec == "^1.30.0"
    assert refs[0].dependency_group == DependencyGroup.OPTIONAL  # edge case 9


def test_poetry_legacy_dev_dependencies(tmp_path):
    refs = _write_and_parse(tmp_path, """
[tool.poetry.dev-dependencies]
pytest = "^8.0"
""")
    assert refs[0].dependency_group == DependencyGroup.DEV


def test_poetry_modern_groups(tmp_path):
    refs = _write_and_parse(tmp_path, """
[tool.poetry.group.test.dependencies]
pytest = "^8.0"

[tool.poetry.group.main.dependencies]
openai = "^1.0"
""")
    by_name = {r.name: r for r in refs}
    assert by_name["pytest"].dependency_group == DependencyGroup.DEV
    assert by_name["openai"].dependency_group == DependencyGroup.MAIN


def test_poetry_bare_version_is_a_range_not_a_pin(tmp_path):
    # Poetry semantics: a bare version string means a caret range by
    # convention, so it must NOT be classified as an exact pin.
    refs = _write_and_parse(tmp_path, """
[tool.poetry.dependencies]
openai = "1.30.0"
""")
    assert refs[0].version_spec_kind == VersionSpecKind.RANGE


def test_pdm_dev_dependencies(tmp_path):
    refs = _write_and_parse(tmp_path, """
[tool.pdm.dev-dependencies]
test = ["pytest>=8.0"]
""")
    assert refs[0].name == "pytest"
    assert refs[0].dependency_group == DependencyGroup.DEV


def test_uv_dev_dependencies(tmp_path):
    refs = _write_and_parse(tmp_path, """
[tool.uv]
dev-dependencies = ["pytest>=8.0"]
""")
    assert refs[0].name == "pytest"
    assert refs[0].dependency_group == DependencyGroup.DEV


def test_malformed_toml_returns_empty_not_raise(tmp_path):
    path = tmp_path / "pyproject.toml"
    path.write_text("[project\nbroken = ", encoding="utf-8")
    assert parse(path, file_path="pyproject.toml") == []


def test_empty_file_returns_empty(tmp_path):
    refs = _write_and_parse(tmp_path, "")
    assert refs == []
