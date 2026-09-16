"""Cargo.toml — Rust. Verified only against synthetic fixtures (no real
Rust project exists on the development machine at the time of writing).

`[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`, plus the
target-specific form `[target.'cfg(...)'.dependencies]`. A crate entry
with `workspace = true` and no inline version defers its version to the
workspace root's `[workspace.dependencies]`, which this parser does not
resolve (no cross-file resolution, same principle as PLAN.md section
7.2's git-anchor choice) — its `version_spec` is empty and therefore
classified UNPINNED, not guessed at.
"""

from __future__ import annotations

import logging
import tomllib
from pathlib import Path
from typing import Any

from ai_sdk_scanner.models import DependencyGroup, DependencyRef, Ecosystem, VersionSource
from ai_sdk_scanner.parsers.base import classify_version_spec, find_line_number

logger = logging.getLogger(__name__)

_SECTION_GROUPS = (
    ("dependencies", DependencyGroup.MAIN),
    ("dev-dependencies", DependencyGroup.DEV),
    ("build-dependencies", DependencyGroup.DEV),
)


def parse(path: Path, *, file_path: str) -> list[DependencyRef]:
    try:
        text = path.read_text(encoding="utf-8")
        data = tomllib.loads(text)
    except (OSError, tomllib.TOMLDecodeError):
        logger.warning("Could not parse %s", path, exc_info=True)
        return []

    lines = text.splitlines()
    refs: list[DependencyRef] = []
    for section, group in _SECTION_GROUPS:
        table = data.get(section, {})
        if isinstance(table, dict):
            refs.extend(_parse_table(table, group=group, file_path=file_path, lines=lines))

    target = data.get("target", {})
    if isinstance(target, dict):
        for target_spec in target.values():
            if not isinstance(target_spec, dict):
                continue
            for section, group in _SECTION_GROUPS:
                table = target_spec.get(section, {})
                if isinstance(table, dict):
                    refs.extend(
                        _parse_table(table, group=group, file_path=file_path, lines=lines)
                    )

    return refs


def _spec_to_string(spec: Any) -> str:
    if isinstance(spec, str):
        return spec
    if isinstance(spec, dict):
        version = spec.get("version")
        return version if isinstance(version, str) else ""
    return ""


def _parse_table(
    table: dict[str, Any], *, group: DependencyGroup, file_path: str, lines: list[str]
) -> list[DependencyRef]:
    refs: list[DependencyRef] = []
    for name, spec in table.items():
        version_spec = _spec_to_string(spec)
        raw = f"{name} = {spec!r}"

        is_optional = False
        vcs_url: str | None = None
        vcs_ref: str | None = None
        local_path: str | None = None

        if isinstance(spec, dict):
            if spec.get("optional") is True:
                is_optional = True
            git_url = spec.get("git")
            if isinstance(git_url, str):
                vcs_url = git_url
                for ref_key in ("rev", "tag", "branch"):
                    candidate = spec.get(ref_key)
                    if isinstance(candidate, str):
                        vcs_ref = candidate
                        break
            path_value = spec.get("path")
            if isinstance(path_value, str):
                local_path = path_value

        entry_group = (
            DependencyGroup.OPTIONAL
            if is_optional and group == DependencyGroup.MAIN
            else group
        )

        refs.append(
            DependencyRef(
                name=name,
                raw_declaration=raw,
                version_spec=version_spec,
                version_spec_kind=classify_version_spec(version_spec, Ecosystem.CARGO),
                version_source=VersionSource.DECLARED,
                ecosystem=Ecosystem.CARGO,
                dependency_group=entry_group,
                is_direct=True,
                file_path=file_path,
                line_number=find_line_number(lines, name),
                is_optional=is_optional,
                vcs_url=vcs_url,
                vcs_ref=vcs_ref,
                local_path=local_path,
            )
        )
    return refs
