"""Scanner configuration. TOML file with CLI-flag overrides (PLAN.md section 9)."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_DB_PATH = ".apikey-scanner/findings.db"
DEFAULT_MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024
DEFAULT_MAX_LINE_LENGTH = 5000
DEFAULT_MIN_ENTROPY_BASE64 = 4.5
DEFAULT_MIN_ENTROPY_HEX = 3.0
DEFAULT_MIN_CANDIDATE_LENGTH = 20

# Ported from AI-SDK-Scanner's system_scan.py: third-party/vendored code and
# build output are pruned before descending, never filtered after the walk.
DEFAULT_PRUNE_DIRS = frozenset({
    "node_modules", "site-packages", "dist-packages", "vendor",
    ".venv", "venv", "env", ".env-dir", "virtualenv",
    "anaconda3", "miniconda3", "miniforge3", ".conda", "conda-meta", "pkgs",
    ".cargo", ".rustup", ".gradle", ".m2", ".nuget", ".ivy2", ".sbt",
    ".cache", ".npm", ".yarn", ".pnpm-store", ".bun", ".deno",
    ".pyenv", ".rbenv", ".nvm", ".asdf",
    "bower_components", "jspm_packages", ".pub-cache",
    "dist", "build", "target", "out", ".next", ".nuxt", ".svelte-kit",
    ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".git",
})

DEFAULT_LOCKFILE_NAMES = frozenset({
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Cargo.lock", "go.sum", "composer.lock", "Gemfile.lock", "uv.lock",
})

DEFAULT_MINIFIED_SUFFIXES = (".min.js", ".min.css", ".bundle.js", ".map")


@dataclass(slots=True)
class ScannerConfig:
    roots: tuple[str, ...] = ()
    db_path: str = DEFAULT_DB_PATH
    jobs: int = 8
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES
    max_line_length: int = DEFAULT_MAX_LINE_LENGTH
    min_entropy_base64: float = DEFAULT_MIN_ENTROPY_BASE64
    min_entropy_hex: float = DEFAULT_MIN_ENTROPY_HEX
    min_candidate_length: int = DEFAULT_MIN_CANDIDATE_LENGTH
    enable_entropy: bool = True
    track_rotation: bool = False
    hash_authors: bool = False
    disabled_pattern_ids: tuple[str, ...] = ()
    extra_prune_dirs: tuple[str, ...] = ()
    per_repo_file_budget: int = 20_000
    prune_dirs: frozenset[str] = field(default_factory=lambda: DEFAULT_PRUNE_DIRS)


def load_config(path: str | Path | None) -> ScannerConfig:
    cfg = ScannerConfig()
    if path is None:
        return cfg
    with open(path, "rb") as f:
        raw = tomllib.load(f)

    if "roots" in raw:
        cfg.roots = tuple(raw["roots"])
    if "db_path" in raw:
        cfg.db_path = raw["db_path"]
    if "jobs" in raw:
        cfg.jobs = int(raw["jobs"])
    if "max_file_size_bytes" in raw:
        cfg.max_file_size_bytes = int(raw["max_file_size_bytes"])
    if "max_line_length" in raw:
        cfg.max_line_length = int(raw["max_line_length"])
    if "min_entropy_base64" in raw:
        cfg.min_entropy_base64 = float(raw["min_entropy_base64"])
    if "min_entropy_hex" in raw:
        cfg.min_entropy_hex = float(raw["min_entropy_hex"])
    if "min_candidate_length" in raw:
        cfg.min_candidate_length = int(raw["min_candidate_length"])
    if "enable_entropy" in raw:
        cfg.enable_entropy = bool(raw["enable_entropy"])
    if "track_rotation" in raw:
        cfg.track_rotation = bool(raw["track_rotation"])
    if "hash_authors" in raw:
        cfg.hash_authors = bool(raw["hash_authors"])
    if "disabled_pattern_ids" in raw:
        cfg.disabled_pattern_ids = tuple(raw["disabled_pattern_ids"])
    if "extra_prune_dirs" in raw:
        cfg.extra_prune_dirs = tuple(raw["extra_prune_dirs"])
        cfg.prune_dirs = frozenset(cfg.prune_dirs | set(cfg.extra_prune_dirs))
    if "per_repo_file_budget" in raw:
        cfg.per_repo_file_budget = int(raw["per_repo_file_budget"])
    return cfg
