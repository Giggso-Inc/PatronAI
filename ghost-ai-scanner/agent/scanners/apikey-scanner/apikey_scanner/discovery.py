"""Discover git repository roots under configured dev roots.

PLAN.md section 7.1: stop descending the moment a `.git` entry is found --
this prevents a vendored/nested repo from being walked twice and keeps a
single large monorepo from exploding into thousands of "sub-repos".
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

from apikey_scanner.config import ScannerConfig


def discover_repos(root: str | Path, config: ScannerConfig) -> Iterator[Path]:
    root = Path(root)
    if not root.exists():
        return

    stack: list[Path] = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except (PermissionError, OSError):
            continue

        if any(e.name == ".git" for e in entries):
            yield current
            continue  # do not descend into a discovered repo's internals

        for entry in entries:
            if not entry.is_dir(follow_symlinks=False):
                continue
            name_lower = entry.name.lower()
            if name_lower in config.prune_dirs or entry.name in config.prune_dirs:
                continue
            if entry.name.startswith(".") and entry.name not in {".git"}:
                # Skip dotdirs other than .git itself (.vscode, .idea, ...) --
                # they are tool config, never a place a repo's own source lives.
                continue
            stack.append(Path(entry.path))


def discover_all_repos(config: ScannerConfig) -> Iterator[Path]:
    seen: set[Path] = set()
    for root in config.roots:
        for repo_path in discover_repos(root, config):
            resolved = repo_path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            yield resolved
