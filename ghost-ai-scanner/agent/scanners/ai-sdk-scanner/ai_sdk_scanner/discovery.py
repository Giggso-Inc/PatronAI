"""Find dependency manifests in a repo. PLAN.md section 9.

Ignored directories are pruned BEFORE descending into them — never walked
and filtered after. That is the difference between a fast scan and one
that reads tens of thousands of files under `node_modules`.
"""

from __future__ import annotations

import logging
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

_ALWAYS_PRUNED_DIRS = frozenset({
    ".git", "node_modules", ".venv", "venv", "env", "site-packages",
    "vendor", "dist", "build", "target", ".tox", ".mypy_cache",
    ".pytest_cache", "__pycache__", ".next", ".nuxt",
    "bin", "obj",  # .NET build output
})

_GIT_TIMEOUT_SECONDS = 15

# Exact manifest filenames, lowercased. Shared with system_scan.py so
# "is this directory a project?" and "is this file a manifest?" can never
# drift apart. `requirements*.txt` is a prefix pattern rather than an
# exact name, so it is handled by is_manifest_filename() below.
MANIFEST_FILENAMES = frozenset({
    "constraints.txt", "pyproject.toml", "pipfile", "setup.cfg", "setup.py",
    "environment.yml", "environment.yaml",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "pom.xml", "build.gradle", "build.gradle.kts",
    "go.mod",
    "cargo.toml",
    "packages.config", "directory.packages.props",
    "gemfile",
    "composer.json",
})

# Extension-based, not exact-name: any *.csproj/*.fsproj/*.vbproj is a
# .NET project file, whatever it's actually named.
_DOTNET_PROJECT_EXTENSIONS = (".csproj", ".fsproj", ".vbproj")


def is_manifest_filename(filename: str) -> bool:
    """True if `filename` is a dependency manifest this tool recognizes."""
    lower = filename.lower()
    if lower in MANIFEST_FILENAMES:
        return True
    if lower.endswith(_DOTNET_PROJECT_EXTENSIONS):
        return True
    return lower.startswith("requirements") and lower.endswith(".txt")


@dataclass(frozen=True, slots=True)
class DiscoveredManifest:
    """One manifest file found on disk, classified but not yet parsed."""

    abs_path: Path
    file_path: str  # repo-relative, forward slashes
    kind: str  # e.g. "python_requirements", "node_package_json"


def _classify(filename: str, parent_dir_name: str) -> str | None:
    """Map a filename (+ its parent dir, for the requirements/*.txt case)
    to a manifest kind, or None if it isn't a manifest we recognize."""
    lower = filename.lower()

    if lower == "requirements.txt" or (
        lower.startswith("requirements") and lower.endswith(".txt")
    ):
        return "python_requirements"
    if parent_dir_name.lower() == "requirements" and lower.endswith(".txt"):
        return "python_requirements"
    if lower == "constraints.txt":
        return "python_constraints"
    if lower == "pyproject.toml":
        return "python_pyproject"
    if lower == "pipfile":
        return "python_pipfile"
    if lower == "setup.cfg":
        return "python_setup_cfg"
    if lower == "setup.py":
        return "python_setup_py_unparsed"  # PLAN.md section 4.3 — recognized, not parsed
    if lower in ("environment.yml", "environment.yaml"):
        return "python_environment_yml"

    if lower == "package.json":
        return "node_package_json"
    if lower == "package-lock.json":
        return "node_lock_npm"
    if lower == "yarn.lock":
        return "node_lock_yarn"
    if lower == "pnpm-lock.yaml":
        return "node_lock_pnpm"

    if lower == "pom.xml":
        return "java_maven"
    if lower in ("build.gradle", "build.gradle.kts"):
        return "java_gradle"

    if lower == "go.mod":
        return "go_mod"

    if lower == "cargo.toml":
        return "rust_cargo"

    if lower.endswith(_DOTNET_PROJECT_EXTENSIONS):
        return "dotnet_project"
    if lower == "packages.config":
        return "dotnet_packages_config"
    if lower == "directory.packages.props":
        return "dotnet_central_packages"

    if lower == "gemfile":
        return "ruby_gemfile"

    if lower == "composer.json":
        return "php_composer"

    return None


def _walk_pruned(
    root: Path, *, max_depth: int | None, max_files: int | None = None
) -> tuple[list[Path], bool]:
    """Yield every file under root, never descending into a pruned dir and
    never following symlinks (PLAN.md section 9).

    Returns (files, truncated). `max_files` is a safety budget for the
    pathological case found in real-world testing: a project containing a
    large ML dataset directory (316k files in one `data/` folder) made an
    unbounded walk take 56 seconds by itself. Pruning `data/` by name
    would be wrong — plenty of projects have a small, legitimate one — so
    the walk is budgeted instead, and `truncated` is surfaced to the
    caller so an incomplete result is never reported as a clean one.
    """
    files: list[Path] = []
    stack: list[tuple[Path, int]] = [(root, 0)]
    truncated = False

    def over_budget() -> bool:
        return max_files is not None and len(files) >= max_files

    while stack and not truncated:
        current, depth = stack.pop()
        if max_depth is not None and depth > max_depth:
            continue
        try:
            entries = list(os.scandir(current))
        except PermissionError:
            # The normal case at system scope: Windows junction points in
            # the user profile ("My Documents", "Cookies", ...) and other
            # users' directories. Logged at DEBUG without a traceback --
            # at WARNING with exc_info these buried real output under
            # dozens of stack traces during live system scanning.
            logger.debug("Permission denied listing %s", current)
            continue
        except OSError:
            logger.warning("Could not list %s", current, exc_info=True)
            continue

        for entry in entries:
            # Checked per-entry, not just per-directory: a single directory
            # holding hundreds of thousands of files would otherwise blow
            # straight past the budget and still report truncated=False.
            if over_budget():
                truncated = True
                logger.warning(
                    "Walk of %s stopped at the %d-file budget; "
                    "manifest discovery may be incomplete",
                    root, max_files,
                )
                break
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry.name in _ALWAYS_PRUNED_DIRS:
                        continue
                    stack.append((Path(entry.path), depth + 1))
                elif entry.is_file(follow_symlinks=False):
                    files.append(Path(entry.path))
            except OSError:
                continue

    return files, truncated


def _gitignored_paths(repo_root: Path, candidates: list[Path]) -> frozenset[Path]:
    """Batch-check which candidates git would ignore, via one `check-ignore`
    call rather than reimplementing gitignore semantics (PLAN.md section 9).

    Uses raw bytes for `input`, deliberately NOT `text=True`: Python's
    text-mode subprocess pipes on Windows translate embedded `\\n` in the
    input string to `\\r\\n` on write. That silently appends a stray `\\r`
    to every path except the last one in the batch, which breaks git's
    exact-match ignore check for everything but the final entry — a real
    bug found via testing, not a theoretical one.
    """
    if not candidates:
        return frozenset()
    rel_paths = [str(p.relative_to(repo_root)) for p in candidates]
    try:
        result = subprocess.run(
            ["git", "check-ignore", "--stdin"],
            cwd=repo_root,
            input="\n".join(rel_paths).encode("utf-8"),
            capture_output=True,
            timeout=_GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return frozenset()
    ignored_rel = set(result.stdout.decode("utf-8", errors="replace").splitlines())
    return frozenset(repo_root / rel for rel in ignored_rel)


def discover_manifests(
    repo_root: Path,
    *,
    include_vendored: bool = False,
    respect_gitignore: bool = True,
    is_git_repo: bool = False,
    max_depth: int | None = None,
    max_files: int | None = None,
) -> tuple[list[DiscoveredManifest], bool]:
    """Walk `repo_root` and return (manifests, walk_truncated).

    `walk_truncated` is True when the `max_files` budget stopped the walk
    early — the caller must surface that, since a truncated walk can miss
    manifests and would otherwise look identical to a project that simply
    has none.
    """
    all_files, truncated = _walk_pruned(
        repo_root, max_depth=max_depth, max_files=max_files
    )

    candidates = [
        f for f in all_files if _classify(f.name, f.parent.name) is not None
    ]

    if not include_vendored:
        # _ALWAYS_PRUNED_DIRS already stops descent into vendor trees; this
        # is a second check for a manifest sitting directly in one that a
        # caller passed as `repo_root` itself (rare, but keeps the flag honest).
        candidates = [
            f for f in candidates
            if not any(part in _ALWAYS_PRUNED_DIRS for part in f.relative_to(repo_root).parts)
        ]

    if respect_gitignore and is_git_repo:
        ignored = _gitignored_paths(repo_root, candidates)
        candidates = [f for f in candidates if f not in ignored]

    manifests: list[DiscoveredManifest] = []
    for f in candidates:
        kind = _classify(f.name, f.parent.name)
        assert kind is not None  # filtered above
        rel = f.relative_to(repo_root).as_posix()
        manifests.append(DiscoveredManifest(abs_path=f, file_path=rel, kind=kind))

    return manifests, truncated
