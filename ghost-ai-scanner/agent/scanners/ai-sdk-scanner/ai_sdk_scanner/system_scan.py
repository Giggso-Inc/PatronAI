"""Whole-system project discovery and scanning.

Extends the single-repo pipeline to answer "which projects on this machine
reference AI libraries, and where". Design notes that matter:

1. PERFORMANCE IS THE PROBLEM, not logic. A naive full-drive walk reads
   millions of files. Every directory in `_SYSTEM_PRUNED_DIRS` and
   `_PACKAGE_CACHE_DIRS` is pruned BEFORE descending, and discovery stops
   descending the moment it identifies a project root.

2. THIRD-PARTY CODE MUST BE PRUNED, not just deprioritized.
   `site-packages`, `anaconda3/pkgs`, `node_modules`, and language package
   caches each contain thousands of manifests belonging to libraries the
   user never wrote. Left in, they would dominate the output and bury the
   user's actual projects — see `_PACKAGE_CACHE_DIRS`.

3. Permission errors are the normal case at system scope (other users'
   directories, Windows internals). They are counted and reported, never
   raised.
"""

from __future__ import annotations

import logging
import os
import socket
import string
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

from ai_sdk_scanner.catalog.loader import Catalog
from ai_sdk_scanner.discovery import is_manifest_filename
from ai_sdk_scanner.models import (
    DiscoveredProject,
    ScanReport,
    SystemScanReport,
    SystemScanSummary,
)
from ai_sdk_scanner.pipeline import run_scan

logger = logging.getLogger(__name__)

# OS/vendor directories that never contain a user's own project.
_SYSTEM_PRUNED_DIRS = frozenset({
    # Windows
    "windows", "$recycle.bin", "system volume information", "recovery",
    "perflogs", "msocache", "config.msi", "$windows.~bt", "$windows.~ws",
    "programdata", "program files", "program files (x86)",
    # macOS / Linux
    "/system", "/library", "/private", "/proc", "/sys", "/dev", "/run",
    "system", "library", "proc", "sys", "dev",
})

# Third-party package stores. These hold thousands of manifests belonging
# to installed libraries, not to the user's projects (design note 2).
_PACKAGE_CACHE_DIRS = frozenset({
    "node_modules", "site-packages", "dist-packages", "vendor",
    ".venv", "venv", "env", ".env", "virtualenv",
    "anaconda3", "miniconda3", "miniforge3", ".conda", "conda-meta", "pkgs",
    ".cargo", ".rustup", ".gradle", ".m2", ".nuget", ".ivy2", ".sbt",
    ".cache", ".npm", ".yarn", ".pnpm-store", ".bun", ".deno",
    ".pyenv", ".rbenv", ".nvm", ".asdf", ".local",
    "bower_components", "jspm_packages", ".pub-cache", "go",
    # Build/tool output
    "dist", "build", "target", "out", ".next", ".nuxt", ".svelte-kit",
    ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "__pycache__", ".git", ".hg", ".svn", ".idea", ".vscode-server",
    "appdata",
})

_HIDDEN_ALLOWLIST = frozenset({".github", ".claude", ".raven"})

# Container directories that are never themselves a project root, even
# when a manifest sits directly in them. Found in live system testing: a
# stray `package.json` in the user's home directory made discovery treat
# ALL of $HOME as one project and stop descending, hiding every real
# project underneath it behind long relative paths. A `.git` directory is
# an unambiguous project boundary; a bare manifest in a container folder
# is not. Discovery keeps descending through these, so a stray manifest
# sitting directly in one is deliberately not reported.
_NEVER_PROJECT_ROOT = frozenset({
    "desktop", "documents", "downloads", "onedrive", "users", "home",
    "pictures", "videos", "music", "public", "temp", "tmp",
    "my documents", "dropbox", "google drive",
})

_DEFAULT_MAX_DEPTH = 12

# Per-project file-examination budget for manifest discovery. Real-world
# testing found a single project whose `data/` directory held 316k dataset
# files, making its unbounded manifest walk take 56s on its own — longer
# than scanning the other 48 projects combined. Projects that hit this
# budget are flagged `walk_truncated` rather than silently reported as
# complete. Raise it with --max-files-per-project.
_DEFAULT_MAX_FILES_PER_PROJECT = 20_000


def default_roots(*, all_drives: bool = True) -> list[Path]:
    """Sensible scan roots for the current OS.

    On Windows that means every fixed drive; elsewhere the user's home
    plus common shared code locations. `--roots` overrides this entirely.
    """
    if sys.platform.startswith("win"):
        if not all_drives:
            return [Path.home()]
        roots: list[Path] = []
        for letter in string.ascii_uppercase:
            drive = Path(f"{letter}:/")
            try:
                if drive.exists():
                    roots.append(drive)
            except OSError:
                continue
        return roots or [Path.home()]

    roots = [Path.home()]
    for extra in ("/opt", "/srv", "/usr/local/src", "/workspace", "/code"):
        p = Path(extra)
        if p.is_dir():
            roots.append(p)
    return roots


@lru_cache(maxsize=1)
def _home_resolved() -> Path:
    return Path.home().resolve()


def _should_prune(name: str) -> bool:
    lower = name.lower()
    if lower in _SYSTEM_PRUNED_DIRS or lower in _PACKAGE_CACHE_DIRS:
        return True
    # Hidden directories are pruned by default: they are overwhelmingly
    # tool state, not projects. A short allowlist keeps the useful ones.
    return lower.startswith(".") and lower not in _HIDDEN_ALLOWLIST


class _DiscoveryStats:
    __slots__ = ("dirs_visited", "dirs_pruned", "access_denied")

    def __init__(self) -> None:
        self.dirs_visited = 0
        self.dirs_pruned = 0
        self.access_denied = 0


def discover_projects(
    roots: list[Path],
    *,
    max_depth: int = _DEFAULT_MAX_DEPTH,
    max_projects: int | None = None,
    progress: bool = False,
) -> tuple[list[DiscoveredProject], _DiscoveryStats]:
    """Walk `roots` and return every project root found.

    A directory is a project root if it contains `.git` (strongest signal)
    or, failing that, any recognized dependency manifest. Discovery STOPS
    descending at a project root — the per-project scan handles everything
    inside it, including nested manifests in a monorepo. Nested git repos
    (submodules, vendored clones) are therefore not reported separately,
    matching PLAN.md edge case 19.
    """
    stats = _DiscoveryStats()
    projects: list[DiscoveredProject] = []
    seen_paths: set[Path] = set()

    for root in roots:
        stack: list[tuple[Path, int]] = [(root, 0)]
        while stack:
            if max_projects is not None and len(projects) >= max_projects:
                logger.warning("Hit --max-projects limit of %d; stopping discovery", max_projects)
                return projects, stats

            current, depth = stack.pop()
            if depth > max_depth:
                continue

            try:
                entries = list(os.scandir(current))
            except (OSError, PermissionError):
                stats.access_denied += 1
                continue

            stats.dirs_visited += 1
            if progress and stats.dirs_visited % 2000 == 0:
                print(
                    f"  ...{stats.dirs_visited} dirs scanned, {len(projects)} projects found",
                    file=sys.stderr,
                )

            subdirs: list[Path] = []
            has_git = False
            has_manifest = False

            for entry in entries:
                try:
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        if entry.name == ".git":
                            has_git = True
                        elif _should_prune(entry.name):
                            stats.dirs_pruned += 1
                        else:
                            subdirs.append(Path(entry.path))
                    elif entry.is_file(follow_symlinks=False) and is_manifest_filename(entry.name):
                        has_manifest = True
                except OSError:
                    continue

            resolved = current.resolve()
            # A git root is always a project boundary. A bare manifest is
            # only one if this isn't a container directory (see
            # _NEVER_PROJECT_ROOT) or the user's home directory itself.
            is_container = (
                resolved.name.lower() in _NEVER_PROJECT_ROOT
                or resolved == _home_resolved()
                # A drive/filesystem root (C:\, /) is never a project root.
                # `.anchor` is a str, so it must be wrapped -- comparing a
                # Path to a str is silently always False (caught by mypy).
                or resolved == Path(resolved.anchor)
            )
            is_project = has_git or (has_manifest and not is_container)

            if is_project and resolved not in seen_paths:
                seen_paths.add(resolved)
                projects.append(
                    DiscoveredProject(
                        path=str(resolved),
                        discovered_by="git_repo" if has_git else "manifest_only",
                    )
                )
                continue  # do not descend into an identified project

            stack.extend((d, depth + 1) for d in subdirs)

    return projects, stats


def run_system_scan(
    catalog: Catalog,
    *,
    roots: list[Path] | None = None,
    all_drives: bool = True,
    max_depth: int = _DEFAULT_MAX_DEPTH,
    max_projects: int | None = None,
    include_transitive: bool = False,
    include_vendored: bool = False,
    respect_gitignore: bool = True,
    with_file_commits: bool = False,
    only_with_matches: bool = True,
    workers: int | None = None,
    max_files_per_project: int | None = _DEFAULT_MAX_FILES_PER_PROJECT,
    ai_only: bool = False,
    progress: bool = False,
) -> SystemScanReport:
    """Discover every project on this machine, then scan each one."""
    scan_timestamp = datetime.now(UTC).isoformat()
    started = datetime.now(UTC)

    scan_roots = roots if roots is not None else default_roots(all_drives=all_drives)

    if progress:
        root_list = ", ".join(str(r) for r in scan_roots)
        print(f"Discovering projects under: {root_list}", file=sys.stderr)

    discovered, stats = discover_projects(
        scan_roots, max_depth=max_depth, max_projects=max_projects, progress=progress
    )

    if progress:
        print(f"Found {len(discovered)} project(s); scanning each...", file=sys.stderr)

    # Scanning a project spawns ~5 git subprocesses (is-repo, remote,
    # rev-parse, status, check-ignore). Measured on a real drive, that
    # subprocess overhead — not the directory walk — dominates total
    # runtime, so the per-project scans run on a thread pool. The work is
    # I/O/subprocess-bound, so threads (not processes) are the right tool:
    # the GIL is released while waiting on each child process.
    def _scan_one(project: DiscoveredProject) -> ScanReport | None:
        try:
            report = run_scan(
                Path(project.path),
                catalog,
                include_vendored=include_vendored,
                respect_gitignore=respect_gitignore,
                include_transitive=include_transitive,
                with_file_commits=with_file_commits,
                max_files=max_files_per_project,
                ai_only=ai_only,
            )
        except Exception:  # noqa: BLE001 - one bad project must never abort the sweep
            logger.warning("Scan failed for %s", project.path, exc_info=True)
            return None

        # Stamp project context onto every record so a flat JSONL row is
        # self-describing: which project it came from, and why that
        # directory was considered a project at all.
        project_name = Path(project.path).name
        enriched = tuple(
            replace(
                r,
                project_root=project.path,
                project_name=project_name,
                project_discovered_by=project.discovered_by,
            )
            for r in report.records
        )
        return replace(report, project_root=project.path, records=enriched)

    project_reports: list[ScanReport] = []
    max_workers = workers or min(16, (os.cpu_count() or 4) * 2)

    if discovered:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = [pool.submit(_scan_one, p) for p in discovered]
            for i, future in enumerate(futures, start=1):
                if progress and i % 25 == 0:
                    print(f"  ...scanned {i}/{len(discovered)} projects", file=sys.stderr)
                report = future.result()
                if report is None:
                    continue
                if only_with_matches and not report.records:
                    continue
                project_reports.append(report)

    duration_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)

    all_records = [r for p in project_reports for r in p.records]
    ai_records = [r for r in all_records if r.is_ai_related]
    # Counted from is_git_repo, not `commit_sha is not None`: a freshly
    # git-init-ed repo with no commits yet has no sha but IS a git repo,
    # and the old inference miscounted it as manifest-only.
    git_count = sum(1 for p in project_reports if p.is_git_repo)

    summary = SystemScanSummary(
        projects_found=len(discovered),
        projects_with_ai_refs=sum(
            1 for p in project_reports if any(r.is_ai_related for r in p.records)
        ),
        projects_with_any_refs=sum(1 for p in project_reports if p.records),
        total_references=len(all_records),
        ai_references=len(ai_records),
        unique_dependencies=len({(r.ecosystem, r.normalized_name) for r in all_records}),
        unique_ai_dependencies=len({(r.ecosystem, r.normalized_name) for r in ai_records}),
        git_projects=git_count,
        manifest_only_projects=len(project_reports) - git_count,
    )

    warnings: list[str] = []
    if max_projects is not None and len(discovered) >= max_projects:
        warnings.append("max_projects_limit_reached")
    if stats.access_denied:
        warnings.append(f"access_denied_on_{stats.access_denied}_directories")

    return SystemScanReport(
        host=socket.gethostname(),
        scan_timestamp=scan_timestamp,
        tool_version=_tool_version(),
        duration_ms=duration_ms,
        roots_scanned=tuple(str(r) for r in scan_roots),
        dirs_pruned=stats.dirs_pruned,
        dirs_visited=stats.dirs_visited,
        access_denied_count=stats.access_denied,
        projects=tuple(project_reports),
        summary=summary,
        warnings=tuple(warnings),
    )


def _tool_version() -> str:
    from ai_sdk_scanner import __version__

    return __version__
