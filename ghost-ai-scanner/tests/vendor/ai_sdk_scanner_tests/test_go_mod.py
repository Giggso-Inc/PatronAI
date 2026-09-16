"""go.mod. No real Go project exists on this machine — verified only
against synthetic fixtures."""

from __future__ import annotations

from ai_sdk_scanner.models import VersionSpecKind
from ai_sdk_scanner.parsers.go_mod import parse


def _write_and_parse(tmp_path, content):
    path = tmp_path / "go.mod"
    path.write_text(content, encoding="utf-8")
    return parse(path, file_path="go.mod")


def test_single_line_require(tmp_path):
    content = (
        "module example.com/foo\n\ngo 1.21\n\n"
        "require github.com/sashabaranov/go-openai v1.20.0\n"
    )
    refs = _write_and_parse(tmp_path, content)
    assert len(refs) == 1
    r = refs[0]
    assert r.name == "github.com/sashabaranov/go-openai"
    assert r.version_spec == "v1.20.0"
    assert r.version_spec_kind == VersionSpecKind.PINNED
    assert r.is_direct is True


def test_block_form_multiple_requires(tmp_path):
    refs = _write_and_parse(tmp_path, """module example.com/foo

require (
    github.com/pkg/errors v0.9.1
    golang.org/x/sys v0.5.0
)
""")
    names = {r.name for r in refs}
    assert names == {"github.com/pkg/errors", "golang.org/x/sys"}


def test_indirect_comment_sets_is_direct_false(tmp_path):
    refs = _write_and_parse(tmp_path, """require (
    github.com/pkg/errors v0.9.1
    golang.org/x/sys v0.5.0 // indirect
)
""")
    by_name = {r.name: r for r in refs}
    assert by_name["github.com/pkg/errors"].is_direct is True
    assert by_name["golang.org/x/sys"].is_direct is False


def test_module_and_go_directives_are_not_dependencies(tmp_path):
    refs = _write_and_parse(tmp_path, "module example.com/foo\n\ngo 1.21\n\ntoolchain go1.21.0\n")
    assert refs == []


def test_replace_and_exclude_are_not_emitted(tmp_path):
    refs = _write_and_parse(tmp_path, """module example.com/foo

require github.com/real/dep v1.0.0

replace github.com/old/pkg => github.com/new/pkg v2.0.0
exclude github.com/bad/pkg v1.0.0
""")
    assert [r.name for r in refs] == ["github.com/real/dep"]


def test_pseudo_version_is_still_pinned(tmp_path):
    refs = _write_and_parse(
        tmp_path,
        "require github.com/x/y v0.0.0-20210101000000-abcdef123456\n",
    )
    assert refs[0].version_spec_kind == VersionSpecKind.PINNED


def test_line_number_recorded_for_both_forms(tmp_path):
    refs = _write_and_parse(tmp_path, """module x

require github.com/single/dep v1.0.0

require (
    github.com/block/dep v2.0.0
)
""")
    by_name = {r.name: r.line_number for r in refs}
    assert by_name["github.com/single/dep"] == 3
    assert by_name["github.com/block/dep"] == 6
