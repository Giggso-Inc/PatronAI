"""Git provenance for a repository as a whole. PLAN.md section 7.1.

Ported from AI-SDK-Scanner's git_context.py (`normalize_remote_url`, the
`_run_git` subprocess wrapper, and the `.rstrip("\\r\\n")` fix for
porcelain output) -- these are the same real bugs the sibling project hit
and fixed, so they are inherited rather than re-discovered here.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

from apikey_scanner.models import RepoContext

_GIT_TIMEOUT_SECONDS = 15
_SSH_REMOTE_RE = re.compile(r"^git@([^:]+):(.+?)(\.git)?/?$")
_HTTPS_REMOTE_RE = re.compile(r"^https?://(?:[^@/]+@)?([^/]+)/(.+?)(\.git)?/?$")


def run_git(repo_path: Path, args: list[str]) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=repo_path,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    # .rstrip(), not .strip(): porcelain output's leading column can be a
    # meaningful literal space -- stripping it corrupts positional parsing.
    return result.stdout.rstrip("\r\n")


def normalize_remote_url(url: str) -> str | None:
    url = url.strip()
    match = _SSH_REMOTE_RE.match(url) or _HTTPS_REMOTE_RE.match(url)
    if not match:
        return None
    host, path = match.group(1), match.group(2)
    return f"{host.lower()}/{path.strip('/')}"


def build_repo_context(repo_path: Path) -> RepoContext:
    is_repo = run_git(repo_path, ["rev-parse", "--is-inside-work-tree"]) == "true"
    if not is_repo:
        digest = hashlib.sha256(str(repo_path.resolve()).encode()).hexdigest()[:8]
        fallback_id = f"local/{repo_path.name}-{digest}"
        return RepoContext(
            repo_id=fallback_id,
            repo_path=str(repo_path),
            is_git_repo=False,
            head_sha=None,
            branch=None,
            remote_url=None,
        )

    head_sha = run_git(repo_path, ["rev-parse", "HEAD"])
    branch = run_git(repo_path, ["rev-parse", "--abbrev-ref", "HEAD"])
    remote_raw = run_git(repo_path, ["remote", "get-url", "origin"])

    repo_id = None
    if remote_raw:
        repo_id = normalize_remote_url(remote_raw)
    if repo_id is None:
        digest = hashlib.sha256(str(repo_path.resolve()).encode()).hexdigest()[:8]
        repo_id = f"local/{repo_path.name}-{digest}"

    return RepoContext(
        repo_id=repo_id,
        repo_path=str(repo_path),
        is_git_repo=True,
        head_sha=head_sha,
        branch=branch,
        remote_url=remote_raw,
    )


def _git_exit_code(repo_path: Path, args: list[str]) -> int | None:
    """Like _run_git, but for commands where the exit code itself is the
    answer (check-ignore: 0=ignored/1=not; ls-files --error-unmatch:
    0=tracked/1=not) and stdout is irrelevant.
    """
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=repo_path,
            capture_output=True,
            timeout=_GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.returncode


def is_path_gitignored(repo_path: Path, file_repo_relative: str) -> bool:
    code = _git_exit_code(repo_path, ["check-ignore", "-q", file_repo_relative])
    return code == 0


def is_path_tracked(repo_path: Path, file_repo_relative: str) -> bool:
    code = _git_exit_code(repo_path, ["ls-files", "--error-unmatch", file_repo_relative])
    return code == 0
