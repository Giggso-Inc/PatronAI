"""Gemfile. No real Ruby project exists on this machine — verified only
against synthetic fixtures."""

from __future__ import annotations

from ai_sdk_scanner.models import DependencyGroup, VersionSpecKind
from ai_sdk_scanner.parsers.ruby_gemfile import parse


def _write_and_parse(tmp_path, content):
    path = tmp_path / "Gemfile"
    path.write_text(content, encoding="utf-8")
    return parse(path, file_path="Gemfile")


def test_bare_gem_no_version(tmp_path):
    refs = _write_and_parse(tmp_path, "gem 'sidekiq'\n")
    assert len(refs) == 1
    assert refs[0].name == "sidekiq"
    assert refs[0].version_spec == ""
    assert refs[0].version_spec_kind == VersionSpecKind.UNPINNED


def test_bare_version_is_exact_by_ruby_convention(tmp_path):
    # RubyGems convention: an operator-less requirement means "=" -- the
    # opposite default from Cargo/Poetry.
    refs = _write_and_parse(tmp_path, "gem 'openai', '0.9.0'\n")
    assert refs[0].version_spec_kind == VersionSpecKind.PINNED


def test_pessimistic_operator_is_a_range(tmp_path):
    refs = _write_and_parse(tmp_path, "gem 'rails', '~> 7.0'\n")
    assert refs[0].version_spec_kind == VersionSpecKind.RANGE


def test_double_quotes_work_too(tmp_path):
    refs = _write_and_parse(tmp_path, 'gem "pg", ">= 1.1"\n')
    assert refs[0].name == "pg"
    assert refs[0].version_spec_kind == VersionSpecKind.RANGE


def test_group_test_block_maps_to_dev(tmp_path):
    refs = _write_and_parse(tmp_path, """gem 'rails', '7.0'

group :test do
  gem 'rspec-rails'
end
""")
    by_name = {r.name: r for r in refs}
    assert by_name["rails"].dependency_group == DependencyGroup.MAIN
    assert by_name["rspec-rails"].dependency_group == DependencyGroup.DEV


def test_group_development_and_test_multi_symbol(tmp_path):
    refs = _write_and_parse(tmp_path, """group :development, :test do
  gem 'pry'
end
""")
    assert refs[0].dependency_group == DependencyGroup.DEV


def test_gems_outside_any_group_are_main(tmp_path):
    refs = _write_and_parse(tmp_path, """group :test do
  gem 'rspec'
end

gem 'sidekiq'
""")
    by_name = {r.name: r for r in refs}
    assert by_name["sidekiq"].dependency_group == DependencyGroup.MAIN


def test_git_source(tmp_path):
    refs = _write_and_parse(tmp_path, "gem 'my_fork', git: 'https://github.com/me/fork.git'\n")
    assert refs[0].vcs_url == "https://github.com/me/fork.git"
    assert refs[0].version_spec_kind == VersionSpecKind.URL


def test_github_shorthand(tmp_path):
    refs = _write_and_parse(tmp_path, "gem 'my_fork', github: 'me/fork'\n")
    assert refs[0].vcs_url == "https://github.com/me/fork"


def test_path_source(tmp_path):
    refs = _write_and_parse(tmp_path, "gem 'local_gem', path: '../local_gem'\n")
    assert refs[0].local_path == "../local_gem"


def test_comment_line_is_ignored(tmp_path):
    refs = _write_and_parse(tmp_path, "# gem 'ignored', '1.0'\ngem 'real', '1.0'\n")
    assert len(refs) == 1
    assert refs[0].name == "real"
