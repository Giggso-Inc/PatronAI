"""Orchestration: expand registry roots, probe existence, resolve profiles,
and fan the I/O-bound extension enumeration out across threads.

PLAN.md section 7: root existence is checked before any thread spawns
(rule 3), and parallelism happens at profile granularity (rule 5) —
coarse enough to amortize task overhead, fine enough to saturate I/O.
"""

from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from extension_searcher.models import BrowserHit, Engine, ExtensionRecord, ProfileHit, ScanError
from extension_searcher.parsers import chromium, gecko, safari, trident
from extension_searcher.platform_probe import current_os, is_macos, is_windows, resolve_root
from extension_searcher.registry import ALL_BROWSERS, BrowserSpec

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ScanTask:
    """One profile's worth of extension-enumeration work."""

    spec: BrowserSpec
    profile: ProfileHit


@dataclass(frozen=True, slots=True)
class ScanResult:
    browsers: tuple[BrowserHit, ...]
    extensions: tuple[ExtensionRecord, ...]
    errors: tuple[ScanError, ...]
    unverified_paths: tuple[str, ...]


def expand_candidates(spec: BrowserSpec) -> list[Path]:
    """Resolve every path-table row for `spec` on the current OS to a Path."""
    os_name = current_os()
    entries = {"windows": spec.windows, "macos": spec.macos, "linux": spec.linux}.get(
        os_name, ()
    )
    candidates: list[Path] = []
    for entry in entries:
        root = resolve_root(entry.root)
        if root is None:
            continue
        candidates.append(root / entry.subpath)
    return candidates


def _discover_profiles_for(spec: BrowserSpec, root: Path) -> list[ProfileHit]:
    if spec.engine == Engine.CHROMIUM:
        return chromium.discover_profiles(root)
    if spec.engine == Engine.GECKO:
        return gecko.discover_profiles(root, channel=spec.channel)
    return []


def _run_task(
    task: ScanTask, *, include_builtin: bool, include_themes: bool, include_state: bool
) -> tuple[list[ExtensionRecord], list[ScanError]]:
    if task.spec.engine == Engine.CHROMIUM:
        return chromium.list_extensions(
            task.profile,
            task.spec.name,
            task.spec.channel,
            include_builtin=include_builtin,
            include_state=include_state,
        )
    if task.spec.engine == Engine.GECKO:
        records = gecko.list_extensions(
            task.profile,
            task.spec.name,
            task.spec.channel,
            include_builtin=include_builtin,
            include_themes=include_themes,
        )
        return records, []
    return [], []


def run_scan(
    specs: tuple[BrowserSpec, ...] = ALL_BROWSERS,
    *,
    include_builtin: bool = False,
    include_themes: bool = False,
    include_state: bool = True,
    include_webkit: bool = True,
    include_trident: bool = True,
    workers: int | None = None,
) -> ScanResult:
    """PLAN.md section 3 pipeline: registry -> discovery -> parser -> report."""
    os_name = current_os()
    browser_hits: list[BrowserHit] = []
    tasks: list[ScanTask] = []
    unverified_paths: list[str] = []

    # Phase 1 (cheap, sequential): resolve roots and discover profiles.
    for spec in specs:
        candidates = expand_candidates(spec)
        roots_checked = tuple(str(p) for p in candidates)
        if not candidates:
            continue  # This spec has no rows for the current OS at all.

        is_unverified_os = os_name == "macos" and spec.macos_unverified
        if is_unverified_os:
            unverified_paths.extend(roots_checked)

        existing_root = next((p for p in candidates if p.is_dir()), None)
        if existing_root is None:
            browser_hits.append(
                BrowserHit(spec.name, spec.engine, False, roots_checked, (), is_unverified_os)
            )
            continue

        profiles = _discover_profiles_for(spec, existing_root)
        browser_hits.append(
            BrowserHit(
                spec.name, spec.engine, True, roots_checked, tuple(profiles), is_unverified_os
            )
        )
        tasks.extend(ScanTask(spec, profile) for profile in profiles)

    # Phase 2 (I/O-bound, parallel): enumerate extensions per profile.
    all_records: list[ExtensionRecord] = []
    all_errors: list[ScanError] = []
    max_workers = workers or min(32, (os.cpu_count() or 4) * 4)

    if tasks:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = [
                pool.submit(
                    _run_task,
                    task,
                    include_builtin=include_builtin,
                    include_themes=include_themes,
                    include_state=include_state,
                )
                for task in tasks
            ]
            for future in futures:
                try:
                    records, errors = future.result()
                except Exception as exc:  # noqa: BLE001 - never let one task kill the scan
                    logger.warning("Extension enumeration task failed", exc_info=True)
                    all_errors.append(ScanError("unknown", "task_failed", str(exc)))
                    continue
                all_records.extend(records)
                all_errors.extend(errors)

    # Phase 3: the two non-file-based parsers (PLAN.md section 6.8/6.9),
    # each gated to the one OS it can run on — absent, not failing, elsewhere.
    if include_webkit and is_macos():
        hit, records, errors = safari.scan()
        browser_hits.append(hit)
        all_records.extend(records)
        all_errors.extend(errors)
        if hit.unverified:
            unverified_paths.extend(hit.roots_checked)

    if include_trident and is_windows():
        hit, records, errors = trident.scan()
        browser_hits.append(hit)
        all_records.extend(records)
        all_errors.extend(errors)

    return ScanResult(
        browsers=tuple(browser_hits),
        extensions=tuple(all_records),
        errors=tuple(all_errors),
        unverified_paths=tuple(unverified_paths),
    )
