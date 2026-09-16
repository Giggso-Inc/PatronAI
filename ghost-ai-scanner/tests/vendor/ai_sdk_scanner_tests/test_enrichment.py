"""Every metadata field the record collects beyond the original six.

Each of these was previously either parsed-then-discarded, or never
collected at all. A `None`/empty value must mean "the format does not
express this", never "we silently dropped it".
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from ai_sdk_scanner.catalog.loader import load_catalog
from ai_sdk_scanner.normalize import split_vcs_url, split_version_constraints
from ai_sdk_scanner.parsers.base import find_line_number
from ai_sdk_scanner.pipeline import run_scan


def _git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def _scan(tmp_path: Path):
    return run_scan(tmp_path, load_catalog())


def _by_name(report, name: str):
    matches = [r for r in report.records if r.dependency_name == name]
    assert matches, f"{name} not found in {[r.dependency_name for r in report.records]}"
    return matches[0]


# --- Pure helpers -------------------------------------------------------

def test_split_version_constraints_decomposes_clauses():
    assert split_version_constraints(">=1.0,<2") == (">=1.0", "<2")
    assert split_version_constraints("==1.0") == ("==1.0",)
    assert split_version_constraints("") == ()
    # A URL is not a set of version constraints.
    assert split_version_constraints("git+https://x/y@ref") == ()


def test_split_vcs_url_separates_ref():
    url, ref = split_vcs_url("git+https://github.com/openai/openai-python@v1.30.1")
    assert url == "git+https://github.com/openai/openai-python"
    assert ref == "v1.30.1"


def test_split_vcs_url_without_ref():
    url, ref = split_vcs_url("git+https://github.com/openai/openai-python")
    assert url == "git+https://github.com/openai/openai-python"
    assert ref is None


def test_split_vcs_url_ignores_egg_fragment():
    url, ref = split_vcs_url("git+https://github.com/o/r@main#egg=openai")
    assert ref == "main"
    assert "#egg" not in (url or "")


def test_split_vcs_url_returns_none_for_plain_specifier():
    assert split_vcs_url(">=1.0") == (None, None)


def test_find_line_number_locates_quoted_key():
    lines = ['{', '  "dependencies": {', '    "openai": "^4.0.0"', '  }', '}']
    assert find_line_number(lines, "openai") == 3


def test_find_line_number_returns_none_when_absent():
    assert find_line_number(["nothing here"], "openai") is None


# --- requirements.txt enrichment ---------------------------------------

def test_extras_and_marker_and_constraints_are_kept(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        'langchain[all,serve]>=0.1,<0.3 ; python_version >= "3.9"\n', encoding="utf-8"
    )
    record = _by_name(_scan(tmp_path), "langchain")
    assert record.extras == ("all", "serve")
    assert record.environment_marker == 'python_version >= "3.9"'
    assert record.version_constraints == (">=0.1", "<0.3")
    assert record.normalized_name == "langchain"


def test_line_number_is_exact_for_requirements(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "# a comment\nflask\nopenai>=1.0\n", encoding="utf-8"
    )
    assert _by_name(_scan(tmp_path), "openai").line_number == 3


def test_index_url_applies_to_following_requirements(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "--extra-index-url https://private.example.com/simple\nopenai>=1.0\n",
        encoding="utf-8",
    )
    record = _by_name(_scan(tmp_path), "openai")
    assert record.declared_index_url == "https://private.example.com/simple"


def test_index_url_absent_when_not_declared(tmp_path):
    (tmp_path / "requirements.txt").write_text("openai>=1.0\n", encoding="utf-8")
    assert _by_name(_scan(tmp_path), "openai").declared_index_url is None


def test_vcs_url_and_ref_from_direct_reference(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "openai @ git+https://github.com/openai/openai-python@v1.30.1\n", encoding="utf-8"
    )
    record = _by_name(_scan(tmp_path), "openai")
    assert record.vcs_url == "git+https://github.com/openai/openai-python"
    assert record.vcs_ref == "v1.30.1"


def test_manifest_kind_is_recorded(tmp_path):
    (tmp_path / "requirements.txt").write_text("openai\n", encoding="utf-8")
    assert _by_name(_scan(tmp_path), "openai").manifest_kind == "python_requirements"


def test_manifest_fingerprint_is_recorded(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("openai\n", encoding="utf-8")
    record = _by_name(_scan(tmp_path), "openai")
    assert record.manifest_sha256 is not None
    assert len(record.manifest_sha256) == 64
    # Compare against the real on-disk size: Python's text-mode write
    # translates "\n" to "\r\n" on Windows, so the byte count does not
    # match len() of the source string.
    assert record.manifest_size == manifest.stat().st_size
    assert record.manifest_mtime is not None


def test_fingerprint_changes_when_manifest_changes(tmp_path):
    (tmp_path / "requirements.txt").write_text("openai\n", encoding="utf-8")
    first = _by_name(_scan(tmp_path), "openai").manifest_sha256
    (tmp_path / "requirements.txt").write_text("openai\nanthropic\n", encoding="utf-8")
    second = _by_name(_scan(tmp_path), "openai").manifest_sha256
    assert first != second


# --- pyproject.toml enrichment -----------------------------------------

def test_poetry_git_source_is_decomposed(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry.dependencies]\n'
        'openai = {git = "https://github.com/openai/openai-python", branch = "main"}\n',
        encoding="utf-8",
    )
    record = _by_name(_scan(tmp_path), "openai")
    assert record.vcs_url == "https://github.com/openai/openai-python"
    assert record.vcs_ref == "main"


def test_poetry_rev_wins_over_branch(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry.dependencies]\n'
        'openai = {git = "https://x/y", rev = "abc123", branch = "main"}\n',
        encoding="utf-8",
    )
    assert _by_name(_scan(tmp_path), "openai").vcs_ref == "abc123"


def test_poetry_local_path_is_recorded(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry.dependencies]\nopenai = {path = "../vendor/openai"}\n', encoding="utf-8"
    )
    assert _by_name(_scan(tmp_path), "openai").local_path == "../vendor/openai"


def test_poetry_optional_flag_is_recorded(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry.dependencies]\nopenai = {version = "^1.0", optional = true}\n',
        encoding="utf-8",
    )
    assert _by_name(_scan(tmp_path), "openai").is_optional is True


def test_poetry_named_source_becomes_index_url(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry.dependencies]\n'
        'openai = {version = "^1.0", source = "internal-mirror"}\n',
        encoding="utf-8",
    )
    assert _by_name(_scan(tmp_path), "openai").declared_index_url == "internal-mirror"


def test_pyproject_line_number_is_best_effort(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = [\n  "openai>=1.0",\n]\n', encoding="utf-8"
    )
    assert _by_name(_scan(tmp_path), "openai").line_number == 4


# --- package.json / lockfile enrichment --------------------------------

def test_package_json_optional_dependency_flag(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"optionalDependencies": {"openai": "^4.0.0"}}), encoding="utf-8"
    )
    assert _by_name(_scan(tmp_path), "openai").is_optional is True


def test_package_json_publish_registry_is_index_url(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({
            "publishConfig": {"registry": "https://npm.internal/"},
            "dependencies": {"openai": "^4.0.0"},
        }),
        encoding="utf-8",
    )
    assert _by_name(_scan(tmp_path), "openai").declared_index_url == "https://npm.internal/"


def test_npm_lockfile_supply_chain_fields(tmp_path):
    (tmp_path / "package-lock.json").write_text(
        json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root"},
                "node_modules/openai": {
                    "version": "4.20.1",
                    "resolved": "https://registry.npmjs.org/openai/-/openai-4.20.1.tgz",
                    "integrity": "sha512-EXAMPLE==",
                    "license": "Apache-2.0",
                    "hasInstallScript": True,
                },
            },
        }),
        encoding="utf-8",
    )
    record = _by_name(_scan(tmp_path), "openai")
    assert record.resolved_url == "https://registry.npmjs.org/openai/-/openai-4.20.1.tgz"
    assert record.integrity == "sha512-EXAMPLE=="
    assert record.declared_license == "Apache-2.0"
    assert record.has_install_script is True


def test_yarn_lock_resolved_and_integrity_are_captured(tmp_path):
    # Regression: these lines come AFTER `version` in a yarn block, and an
    # earlier implementation emitted on the version line and lost both.
    (tmp_path / "yarn.lock").write_text(
        '"openai@^4.20.0":\n'
        '  version "4.21.0"\n'
        '  resolved "https://registry.yarnpkg.com/openai/-/openai-4.21.0.tgz"\n'
        '  integrity sha512-YARNEXAMPLE==\n',
        encoding="utf-8",
    )
    from ai_sdk_scanner.parsers.node_lockfiles import parse_yarn_lock

    refs = parse_yarn_lock(
        tmp_path / "yarn.lock", file_path="yarn.lock", include_transitive=True
    )
    assert len(refs) == 1
    assert refs[0].resolved_url == "https://registry.yarnpkg.com/openai/-/openai-4.21.0.tgz"
    assert refs[0].integrity == "sha512-YARNEXAMPLE=="


# --- git enrichment ----------------------------------------------------

def test_git_branch_remote_and_commit_metadata(tmp_path):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "dev@example.com")
    _git(tmp_path, "config", "user.name", "Dev Person")
    _git(tmp_path, "remote", "add", "origin", "git@github.com:my-org/my-repo.git")
    (tmp_path / "requirements.txt").write_text("openai\n", encoding="utf-8")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-q", "-m", "init")

    report = _scan(tmp_path)
    record = _by_name(report, "openai")
    assert record.git_remote_url == "git@github.com:my-org/my-repo.git"
    assert record.commit_author == "Dev Person"
    assert record.commit_date is not None
    assert record.git_branch in ("main", "master")
    assert report.is_git_repo is True


def test_file_last_commit_metadata_is_opt_in(tmp_path):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "dev@example.com")
    _git(tmp_path, "config", "user.name", "Dev Person")
    (tmp_path / "requirements.txt").write_text("openai\n", encoding="utf-8")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-q", "-m", "init")

    without = run_scan(tmp_path, load_catalog())
    assert _by_name(without, "openai").file_last_commit_author is None

    with_commits = run_scan(tmp_path, load_catalog(), with_file_commits=True)
    record = _by_name(with_commits, "openai")
    assert record.file_last_commit_sha is not None
    assert record.file_last_commit_author == "Dev Person"
    assert record.file_last_commit_date is not None


def test_non_git_project_leaves_git_fields_none(tmp_path):
    (tmp_path / "requirements.txt").write_text("openai\n", encoding="utf-8")
    report = _scan(tmp_path)
    record = _by_name(report, "openai")
    assert report.is_git_repo is False
    assert record.git_branch is None
    assert record.git_remote_url is None
    assert record.commit_author is None
