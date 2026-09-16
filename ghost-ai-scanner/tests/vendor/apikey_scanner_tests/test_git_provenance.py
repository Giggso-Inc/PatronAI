"""Real git fixtures. PLAN.md section 11.3 -- committed, dirty, untracked,
gitignored, no-commits, no-remote. Each must produce the correct
ProvenanceState (section 7.3): never fabricate a sha git could not confirm.
"""

from __future__ import annotations

from pathlib import Path

from apikey_scanner.config import ScannerConfig
from apikey_scanner.models import ProvenanceState
from apikey_scanner.pipeline import scan_repo
from .conftest import commit_all

AWS_SAMPLE = 'aws_key = "AKIAQ7ZP4XKM9LWD2FTR"\n'


def _config() -> ScannerConfig:
    cfg = ScannerConfig()
    cfg.enable_entropy = False
    return cfg


def test_committed_line_has_real_commit_sha(git_repo: Path):
    (git_repo / "app.py").write_text(AWS_SAMPLE, encoding="utf-8")
    sha = commit_all(git_repo, "add key")

    _ctx, findings, _scanned, _skipped = scan_repo(git_repo, _catalog(), _config(), "ts")
    assert len(findings) == 1
    f = findings[0]
    assert f.provenance_state == ProvenanceState.COMMITTED
    assert f.commit_sha == sha
    assert f.author_name == "Tester"
    assert f.author_email == "tester@example.com"
    assert f.author_timestamp is not None
    assert f.is_git_tracked is True
    assert f.is_gitignored is False


def test_uncommitted_change_has_no_sha(git_repo: Path):
    (git_repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    commit_all(git_repo, "initial")
    (git_repo / "app.py").write_text(AWS_SAMPLE, encoding="utf-8")  # dirty, not committed

    _ctx, findings, _scanned, _skipped = scan_repo(git_repo, _catalog(), _config(), "ts")
    assert len(findings) == 1
    f = findings[0]
    assert f.provenance_state == ProvenanceState.UNCOMMITTED_CHANGE
    assert f.commit_sha is None
    assert f.author_name is None


def test_untracked_file_has_no_sha(git_repo: Path):
    (git_repo / "README.md").write_text("hello\n", encoding="utf-8")
    commit_all(git_repo, "initial")
    (git_repo / "app.py").write_text(AWS_SAMPLE, encoding="utf-8")  # never git add'ed

    _ctx, findings, _scanned, _skipped = scan_repo(git_repo, _catalog(), _config(), "ts")
    assert len(findings) == 1
    f = findings[0]
    assert f.provenance_state == ProvenanceState.UNTRACKED
    assert f.commit_sha is None
    assert f.is_git_tracked is False


def test_gitignored_file_is_scanned_and_flagged(git_repo: Path):
    (git_repo / ".gitignore").write_text(".env\n", encoding="utf-8")
    commit_all(git_repo, "add gitignore")
    (git_repo / ".env").write_text(AWS_SAMPLE, encoding="utf-8")

    _ctx, findings, _scanned, _skipped = scan_repo(git_repo, _catalog(), _config(), "ts")
    assert len(findings) == 1
    f = findings[0]
    assert f.provenance_state == ProvenanceState.UNTRACKED
    assert f.is_git_tracked is False
    assert f.is_gitignored is True


def test_repo_with_no_commits_yet(git_repo: Path):
    # git_repo fixture only runs `git init` -- no commits exist.
    (git_repo / "app.py").write_text(AWS_SAMPLE, encoding="utf-8")

    _ctx, findings, _scanned, _skipped = scan_repo(git_repo, _catalog(), _config(), "ts")
    assert len(findings) == 1
    f = findings[0]
    assert f.provenance_state == ProvenanceState.UNTRACKED
    assert f.commit_sha is None


def test_repo_with_no_remote_falls_back_to_local_repo_id(git_repo: Path):
    (git_repo / "app.py").write_text(AWS_SAMPLE, encoding="utf-8")
    commit_all(git_repo, "add key")

    repo_context, findings, _scanned, _skipped = scan_repo(git_repo, _catalog(), _config(), "ts")
    assert repo_context.is_git_repo is True
    assert repo_context.remote_url is None
    assert repo_context.repo_id.startswith("local/")
    assert findings[0].repo_id == repo_context.repo_id


def test_not_a_repo_at_all(tmp_path: Path):
    plain_dir = tmp_path / "plain"
    plain_dir.mkdir()
    (plain_dir / "app.py").write_text(AWS_SAMPLE, encoding="utf-8")

    repo_context, findings, _scanned, _skipped = scan_repo(plain_dir, _catalog(), _config(), "ts")
    assert repo_context.is_git_repo is False
    assert len(findings) == 1
    assert findings[0].provenance_state == ProvenanceState.NOT_A_REPO
    assert findings[0].commit_sha is None


def _catalog():
    from apikey_scanner.catalog.loader import load_catalog

    return load_catalog()
