"""Batched `git blame --porcelain` -- one subprocess per FILE, not per
finding. PLAN.md section 7.2: this is the single largest performance win
in the whole pipeline.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

from apikey_scanner.git_context import run_git
from apikey_scanner.models import GitBlameInfo, ProvenanceState

_ALL_ZERO_SHA = "0" * 40
_HEADER_RE = re.compile(r"^([0-9a-f]{40}) (\d+) (\d+)(?: (\d+))?$")


def _parse_porcelain(output: str) -> dict[int, GitBlameInfo]:
    lines = output.split("\n")
    commit_meta: dict[str, dict[str, str]] = {}
    result: dict[int, GitBlameInfo] = {}

    i = 0
    while i < len(lines):
        line = lines[i]
        header = _HEADER_RE.match(line)
        if header is None:
            i += 1
            continue

        sha, final_line = header.group(1), int(header.group(3))
        i += 1
        meta = commit_meta.get(sha, {})
        while i < len(lines) and not lines[i].startswith("\t"):
            meta_line = lines[i]
            if " " in meta_line:
                key, _, value = meta_line.partition(" ")
                meta[key] = value
            i += 1
        commit_meta[sha] = meta
        if i < len(lines) and lines[i].startswith("\t"):
            i += 1  # skip the source content line -- never inspected here

        if sha == _ALL_ZERO_SHA:
            result[final_line] = GitBlameInfo(
                provenance_state=ProvenanceState.UNCOMMITTED_CHANGE,
                commit_sha=None,
                author_name=None,
                author_email=None,
                author_timestamp=None,
            )
        else:
            author_time = meta.get("author-time")
            timestamp = (
                datetime.fromtimestamp(int(author_time), tz=UTC).isoformat()
                if author_time
                else None
            )
            result[final_line] = GitBlameInfo(
                provenance_state=ProvenanceState.COMMITTED,
                commit_sha=sha,
                author_name=meta.get("author"),
                author_email=meta.get("author-mail", "").strip("<>") or None,
                author_timestamp=timestamp,
            )

    return result


def blame_lines(
    repo_path: Path, file_repo_relative: str, line_numbers: set[int]
) -> dict[int, GitBlameInfo]:
    """Blame every requested line of one file in a single `git blame` call.

    Returns an empty dict if the file cannot be blamed at all (untracked,
    outside a repo, or a git error) -- callers interpret a missing line
    number as ProvenanceState.UNTRACKED, never fabricating a sha.
    """
    if not line_numbers:
        return {}

    args = ["blame", "--porcelain"]
    for n in sorted(line_numbers):
        args += ["-L", f"{n},{n}"]
    args += ["--", file_repo_relative]

    output = run_git(repo_path, args)
    if output is None:
        return {}
    return _parse_porcelain(output)
