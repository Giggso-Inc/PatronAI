"""Git provenance. PLAN.md section 7.

`repo_id` and `commit_sha` are what make a `ScanRecord` traceable to an
exact point in history. Every function here degrades gracefully when the
target is not a git repository at all (section 7.4) — that is a normal
case, not an error.
"""

from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

_GIT_TIMEOUT_SECONDS = 15
_SSH_REMOTE_RE = re.compile(r"^git@([^:]+):(.+?)(\.git)?/?$")
_HTTPS_REMOTE_RE = re.compile(r"^https?://(?:[^@/]+@)?([^/]+)/(.+?)(\.git)?/?$")


_FIELD_SEP = "\x1f"


@dataclass(frozen=True, slots=True)
class GitContext:
    """Everything a scan needs to know about its git provenance."""

    repo_id: str
    commit_sha: str | None
    is_dirty: bool
    is_git_repo: bool
    modified_paths: frozenset[str]  # repo-relative, posix separators
    warnings: tuple[str, ...]
    branch: str | None = None
    remote_url: str | None = None  # raw, before repo_id normalization
    commit_date: str | None = None  # ISO-8601, author date
    commit_author: str | None = None


def _run_git(repo_path: Path, args: list[str]) -> str | None:
    """Run a git command; return stdout with trailing whitespace trimmed.

    Deliberately `.rstrip()`, not `.strip()` — `git status --porcelain`'s
    first status column can be a literal leading space (" M file" means
    unmodified-in-index, modified-in-worktree), and stripping that away
    silently corrupted the first line's column alignment for every caller
    that parses this output positionally (get_modified_paths).
    """
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.rstrip("\r\n")


def is_git_repo(repo_path: Path) -> bool:
    return _run_git(repo_path, ["rev-parse", "--is-inside-work-tree"]) == "true"


def normalize_remote_url(url: str) -> str | None:
    """`git@github.com:org/repo.git` and `https://github.com/org/repo.git`
    both normalize to `github.com/org/repo` (PLAN.md section 7.1)."""
    url = url.strip()
    match = _SSH_REMOTE_RE.match(url) or _HTTPS_REMOTE_RE.match(url)
    if not match:
        return None
    host, path = match.group(1), match.group(2)
    return f"{host.lower()}/{path.strip('/')}"


def resolve_repo_id(repo_path: Path, *, explicit: str | None = None) -> str:
    """PLAN.md section 7.1 resolution order: explicit > remote > local:<dirname>."""
    if explicit:
        return explicit

    remote_url = _run_git(repo_path, ["remote", "get-url", "origin"])
    if remote_url:
        normalized = normalize_remote_url(remote_url)
        if normalized:
            return normalized

    return f"local:{repo_path.resolve().name}"


def get_commit_sha(repo_path: Path) -> str | None:
    """PLAN.md section 7.2, option A: one sha for the whole scan (repo HEAD)."""
    return _run_git(repo_path, ["rev-parse", "HEAD"])


def get_head_commit_info(repo_path: Path) -> tuple[str | None, str | None, str | None]:
    """(sha, author_date_iso, author_name) for HEAD, in ONE git call.

    Batched deliberately: at system scope the per-project subprocess count
    dominates total runtime, so three separate calls for these three
    values would be a measurable regression.
    """
    fmt = f"--format=%H{_FIELD_SEP}%aI{_FIELD_SEP}%an"
    output = _run_git(repo_path, ["log", "-1", fmt])
    if not output:
        return None, None, None
    parts = output.split(_FIELD_SEP)
    if len(parts) != 3:
        return (parts[0] or None) if parts else None, None, None
    return parts[0] or None, parts[1] or None, parts[2] or None


def get_branch(repo_path: Path) -> str | None:
    """Current branch name, or None on a detached HEAD."""
    branch = _run_git(repo_path, ["rev-parse", "--abbrev-ref", "HEAD"])
    if not branch or branch == "HEAD":  # "HEAD" means detached
        return None
    return branch


def get_file_last_commit(repo_path: Path, file_path: str) -> str | None:
    """PLAN.md section 7.2, option B: opt-in per-file last-changed commit."""
    return _run_git(repo_path, ["log", "-1", "--format=%H", "--", file_path])


def get_file_last_commit_info(
    repo_path: Path, file_path: str
) -> tuple[str | None, str | None, str | None]:
    """(sha, author_date_iso, author_name) for the last commit touching
    `file_path`, in one git call. Answers "when did this dependency file
    last change, and who changed it"."""
    fmt = f"--format=%H{_FIELD_SEP}%aI{_FIELD_SEP}%an"
    output = _run_git(repo_path, ["log", "-1", fmt, "--", file_path])
    if not output:
        return None, None, None
    parts = output.split(_FIELD_SEP)
    if len(parts) != 3:
        return (parts[0] or None) if parts else None, None, None
    return parts[0] or None, parts[1] or None, parts[2] or None


def get_modified_paths(repo_path: Path) -> frozenset[str]:
    """Repo-relative, posix-separator paths with uncommitted changes —
    staged, unstaged, or untracked (PLAN.md section 7.3)."""
    output = _run_git(repo_path, ["status", "--porcelain"])
    if not output:
        return frozenset()

    paths: set[str] = set()
    for line in output.splitlines():
        if len(line) < 4:
            continue
        path_part = line[3:]
        # Renames: "old -> new" — the new path is what matters going forward.
        if " -> " in path_part:
            path_part = path_part.split(" -> ", 1)[1]
        paths.add(path_part.strip().strip('"').replace("\\", "/"))
    return frozenset(paths)


def build_git_context(repo_path: Path, *, explicit_repo_id: str | None = None) -> GitContext:
    """Assemble the full git context for one scan, never raising."""
    if not is_git_repo(repo_path):
        fallback_repo_id = explicit_repo_id or f"local:{repo_path.resolve().name}"
        return GitContext(
            repo_id=fallback_repo_id,
            commit_sha=None,
            is_dirty=False,
            is_git_repo=False,
            modified_paths=frozenset(),
            warnings=("no_git_context",),
        )

    remote_url = _run_git(repo_path, ["remote", "get-url", "origin"])
    repo_id = _repo_id_from_remote(repo_path, remote_url, explicit_repo_id)
    commit_sha, commit_date, commit_author = get_head_commit_info(repo_path)
    modified_paths = get_modified_paths(repo_path)
    warnings: list[str] = []
    if commit_sha is None:
        warnings.append("no_commits_yet")

    return GitContext(
        repo_id=repo_id,
        commit_sha=commit_sha,
        is_dirty=bool(modified_paths),
        is_git_repo=True,
        modified_paths=modified_paths,
        warnings=tuple(warnings),
        branch=get_branch(repo_path),
        remote_url=remote_url or None,
        commit_date=commit_date,
        commit_author=commit_author,
    )


def _repo_id_from_remote(
    repo_path: Path, remote_url: str | None, explicit: str | None
) -> str:
    """resolve_repo_id's logic, reusing an already-fetched remote URL so
    build_git_context doesn't spend a second subprocess on it."""
    if explicit:
        return explicit
    if remote_url:
        normalized = normalize_remote_url(remote_url)
        if normalized:
            return normalized
    return f"local:{repo_path.resolve().name}"
