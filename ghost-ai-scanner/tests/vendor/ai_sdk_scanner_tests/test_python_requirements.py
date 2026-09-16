"""requirements.txt / constraints.txt parsing. PLAN.md sections 4.1, 6.1, 11."""

from __future__ import annotations

from ai_sdk_scanner.models import DependencyGroup, VersionSpecKind
from ai_sdk_scanner.parsers.python_requirements import parse


def _write_and_parse(tmp_path, content, filename="requirements.txt", kind="python_requirements"):
    path = tmp_path / filename
    path.write_text(content, encoding="utf-8")
    return parse(path, file_path=filename, kind=kind)


def test_basic_pinned_and_range(tmp_path):
    refs = _write_and_parse(tmp_path, "openai==1.30.1\nanthropic>=0.20,<1\n")
    by_name = {r.name: r for r in refs}
    assert by_name["openai"].version_spec == "==1.30.1"
    assert by_name["openai"].version_spec_kind == VersionSpecKind.PINNED
    assert by_name["anthropic"].version_spec_kind == VersionSpecKind.RANGE


def test_bare_name_is_unpinned(tmp_path):
    refs = _write_and_parse(tmp_path, "openai\n")
    assert refs[0].version_spec_kind == VersionSpecKind.UNPINNED
    assert refs[0].version_spec == ""


def test_whole_line_comment_is_skipped(tmp_path):
    refs = _write_and_parse(tmp_path, "# openai\nanthropic\n")
    assert [r.name for r in refs] == ["anthropic"]


def test_inline_comment_is_stripped(tmp_path):
    refs = _write_and_parse(tmp_path, "openai==1.0  # pinned for stability\n")
    assert refs[0].version_spec == "==1.0"


def test_hash_in_url_fragment_is_not_a_comment(tmp_path):
    refs = _write_and_parse(tmp_path, "openai @ git+https://github.com/openai/openai-python#egg=openai\n")
    assert len(refs) == 1
    assert refs[0].name == "openai"
    assert "egg=openai" in refs[0].version_spec


def test_environment_marker_is_stripped_from_name(tmp_path):
    refs = _write_and_parse(tmp_path, 'openai>=1.0; python_version >= "3.9"\n')
    assert refs[0].name == "openai"
    assert refs[0].version_spec == ">=1.0"


def test_extras_are_stripped_for_matching_but_kept_in_raw(tmp_path):
    refs = _write_and_parse(tmp_path, "langchain[all]==0.1.0\n")
    assert refs[0].name == "langchain"
    assert refs[0].raw_declaration == "langchain[all]==0.1.0"


def test_direct_url_dependency(tmp_path):
    refs = _write_and_parse(
        tmp_path, "openai @ git+https://github.com/openai/openai-python@abc123\n"
    )
    assert refs[0].name == "openai"
    assert refs[0].version_spec_kind == VersionSpecKind.URL


def test_editable_with_egg_name_is_captured(tmp_path):
    refs = _write_and_parse(
        tmp_path, "-e git+https://github.com/openai/openai-python.git#egg=openai\n"
    )
    assert len(refs) == 1
    assert refs[0].name == "openai"


def test_editable_local_path_without_egg_is_skipped(tmp_path):
    refs = _write_and_parse(tmp_path, "-e .\n")
    assert refs == []


def test_include_directive_is_followed(tmp_path):
    (tmp_path / "base.txt").write_text("openai\n", encoding="utf-8")
    refs = _write_and_parse(tmp_path, "-r base.txt\nanthropic\n")
    assert {r.name for r in refs} == {"openai", "anthropic"}


def test_include_cycle_does_not_infinite_loop(tmp_path):
    (tmp_path / "a.txt").write_text("-r b.txt\nopenai\n", encoding="utf-8")
    (tmp_path / "b.txt").write_text("-r a.txt\nanthropic\n", encoding="utf-8")
    refs = _write_and_parse(tmp_path, "-r a.txt\n", filename="requirements.txt")
    names = {r.name for r in refs}
    assert names == {"openai", "anthropic"}  # completes, no infinite recursion


def test_constraints_file_group_is_constraints(tmp_path):
    refs = _write_and_parse(
        tmp_path, "openai==1.0\n", filename="constraints.txt", kind="python_constraints"
    )
    assert refs[0].dependency_group == DependencyGroup.CONSTRAINTS


def test_dev_in_filename_maps_to_dev_group(tmp_path):
    refs = _write_and_parse(tmp_path, "pytest\n", filename="requirements-dev.txt")
    assert refs[0].dependency_group == DependencyGroup.DEV


def test_other_pip_flags_are_ignored(tmp_path):
    refs = _write_and_parse(tmp_path, "--index-url https://example.com/simple\nopenai\n")
    assert [r.name for r in refs] == ["openai"]


def test_blank_lines_are_ignored(tmp_path):
    refs = _write_and_parse(tmp_path, "\n\nopenai\n\n")
    assert [r.name for r in refs] == ["openai"]
