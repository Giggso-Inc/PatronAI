from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from apikey_scanner.catalog.loader import load_catalog
from apikey_scanner.config import ScannerConfig


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )


def init_git_repo(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "tester@example.com")
    _git(repo, "config", "user.name", "Tester")


def commit_all(repo: Path, message: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)
    result = _git(repo, "rev-parse", "HEAD")
    return result.stdout.strip()


@pytest.fixture
def catalog():
    return load_catalog()


@pytest.fixture
def base_config() -> ScannerConfig:
    cfg = ScannerConfig()
    cfg.min_candidate_length = 20
    return cfg


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    init_git_repo(repo)
    return repo
