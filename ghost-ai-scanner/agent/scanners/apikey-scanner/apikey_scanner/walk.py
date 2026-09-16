"""Per-repo file walk: prune dirs, then gate individual files.

PLAN.md section 5.1 -- these gates run BEFORE any regex, cheapest first.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from apikey_scanner.config import DEFAULT_LOCKFILE_NAMES, DEFAULT_MINIFIED_SUFFIXES, ScannerConfig


@dataclass(frozen=True, slots=True)
class WalkedFile:
    abs_path: Path
    repo_relative_posix: str
    is_lockfile: bool
    is_minified: bool


def _is_binary(sample: bytes) -> bool:
    return b"\x00" in sample


def _is_minified(name: str) -> bool:
    lower = name.lower()
    return any(lower.endswith(suffix) for suffix in DEFAULT_MINIFIED_SUFFIXES)


def walk_repo_files(
    repo_root: Path, config: ScannerConfig
) -> Iterator[WalkedFile]:
    """Yield files worth scanning. Skips binaries, oversized files, and
    minified bundles by content/name; does NOT open+read full content here
    (that happens once in the caller) -- only a small header sniff.
    """
    budget = config.per_repo_file_budget
    emitted = 0
    stack: list[Path] = [repo_root]

    while stack and emitted < budget:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except (PermissionError, OSError):
            continue

        for entry in entries:
            if emitted >= budget:
                break
            try:
                if entry.is_dir(follow_symlinks=False):
                    name = entry.name
                    if name in config.prune_dirs or name.lower() in config.prune_dirs:
                        continue
                    stack.append(Path(entry.path))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
            except OSError:
                continue

            name = entry.name
            if _is_minified(name):
                continue

            try:
                size = entry.stat(follow_symlinks=False).st_size
            except OSError:
                continue
            if size == 0 or size > config.max_file_size_bytes:
                continue

            abs_path = Path(entry.path)
            try:
                with open(abs_path, "rb") as f:
                    header = f.read(8192)
            except OSError:
                continue
            if _is_binary(header):
                continue

            try:
                rel = abs_path.relative_to(repo_root).as_posix()
            except ValueError:
                continue

            emitted += 1
            yield WalkedFile(
                abs_path=abs_path,
                repo_relative_posix=rel,
                is_lockfile=name in DEFAULT_LOCKFILE_NAMES,
                is_minified=False,
            )
