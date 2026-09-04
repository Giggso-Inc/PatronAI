"""Git provenance, tested against REAL git behaviour via a tmp_path repo
(PLAN.md section 12: "a real git fixture... so git_context.py is tested
against real git behaviour, not a mock")."""

from __future__ import annotations

import subprocess

import pytest

from ai_sdk_scanner.git_context import (
    build_git_context,
    get_commit_sha,
    get_modified_paths,
    is_git_repo,
    normalize_remote_url,
    resolve_repo_id,
)


def _git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def clean_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    (repo / "requirements.txt").write_text("openai\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "initial")
    return repo


def test_is_git_repo_true_and_false(clean_repo, tmp_path):
    assert is_git_repo(clean_repo) is True
    non_repo = tmp_path / "not_a_repo"
    non_repo.mkdir()
    assert is_git_repo(non_repo) is False


def test_clean_repo_has_commit_and_is_not_dirty(clean_repo):
    ctx = build_git_context(clean_repo)
    assert ctx.is_git_repo is True
    assert ctx.commit_sha is not None
    assert len(ctx.commit_sha) == 40
    assert ctx.is_dirty is False
    assert ctx.modified_paths == frozenset()


def test_dirty_repo_flags_modified_file(clean_repo):
    (clean_repo / "requirements.txt").write_text("openai\nanthropic\n")
    ctx = build_git_context(clean_repo)
    assert ctx.is_dirty is True
    assert "requirements.txt" in ctx.modified_paths


def test_untracked_file_counts_as_dirty(clean_repo):
    (clean_repo / "package.json").write_text("{}")
    ctx = build_git_context(clean_repo)
    assert ctx.is_dirty is True
    assert "package.json" in ctx.modified_paths


def test_non_repo_directory_degrades_gracefully(tmp_path):
    non_repo = tmp_path / "plain_dir"
    non_repo.mkdir()
    ctx = build_git_context(non_repo)
    assert ctx.is_git_repo is False
    assert ctx.commit_sha is None
    assert ctx.is_dirty is False
    assert ctx.repo_id == f"local:{non_repo.name}"
    assert "no_git_context" in ctx.warnings


def test_explicit_repo_id_wins_even_without_git(tmp_path):
    non_repo = tmp_path / "plain_dir2"
    non_repo.mkdir()
    ctx = build_git_context(non_repo, explicit_repo_id="my-org/my-repo")
    assert ctx.repo_id == "my-org/my-repo"


def test_explicit_repo_id_wins_over_remote(clean_repo):
    repo_id = resolve_repo_id(clean_repo, explicit="override/wins")
    assert repo_id == "override/wins"


def test_repo_id_falls_back_to_local_dirname_without_remote(clean_repo):
    repo_id = resolve_repo_id(clean_repo)
    assert repo_id == f"local:{clean_repo.name}"


def test_zero_commits_repo_has_no_commit_sha(tmp_path):
    repo = tmp_path / "empty_repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    assert is_git_repo(repo) is True
    assert get_commit_sha(repo) is None
    ctx = build_git_context(repo)
    assert ctx.commit_sha is None
    assert "no_commits_yet" in ctx.warnings


def test_get_modified_paths_empty_on_clean_repo(clean_repo):
    assert get_modified_paths(clean_repo) == frozenset()


# --- URL normalization (no git needed) --------------------------------------

def test_normalize_ssh_remote():
    assert normalize_remote_url("git@github.com:my-org/my-repo.git") == "github.com/my-org/my-repo"


def test_normalize_https_remote():
    result = normalize_remote_url("https://github.com/my-org/my-repo.git")
    assert result == "github.com/my-org/my-repo"


def test_normalize_https_remote_with_credentials():
    assert normalize_remote_url(
        "https://user:token@github.com/my-org/my-repo.git"
    ) == "github.com/my-org/my-repo"


def test_ssh_and_https_normalize_identically():
    ssh = normalize_remote_url("git@github.com:my-org/my-repo.git")
    https = normalize_remote_url("https://github.com/my-org/my-repo.git")
    assert ssh == https


def test_normalize_unrecognized_url_returns_none():
    assert normalize_remote_url("not a url at all") is None
