"""requirements*.txt and constraints.txt. PLAN.md sections 4.1, 6.1, 11.

PEP 508-ish line grammar: `name[extras]<specifier>; marker`, plus pip's
own `-r`/`-c`/`-e` directives. This is a pragmatic parser, not a full PEP
508 grammar implementation — see the inline notes on where it simplifies.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ai_sdk_scanner.models import DependencyGroup, DependencyRef, Ecosystem, VersionSource
from ai_sdk_scanner.normalize import (
    split_environment_marker,
    split_pep508_name_and_specifier,
    split_vcs_url,
    split_version_constraints,
    strip_extras,
)
from ai_sdk_scanner.parsers.base import classify_version_spec

logger = logging.getLogger(__name__)

_INCLUDE_RE = re.compile(r"^-{1,2}(r|requirement|c|constraint)\b\S*\s+(.+)$", re.IGNORECASE)
_INDEX_URL_RE = re.compile(
    r"^-{1,2}(?:index-url|extra-index-url|i)\b\S*[\s=]+(\S+)", re.IGNORECASE
)
_EDITABLE_RE = re.compile(r"^-{1,2}e(ditable)?\b\S*\s+(.+)$", re.IGNORECASE)
_EGG_NAME_RE = re.compile(r"#egg=([A-Za-z0-9._\-]+)")


def _strip_comment(line: str) -> str:
    """Pip treats a `#` preceded by whitespace (or at line start) as a
    comment start; a `#` glued to a preceding character (as in a URL
    fragment `#egg=name`) is not. This is a pragmatic approximation of
    pip's actual rule, not the full grammar."""
    if line.lstrip().startswith("#"):
        return ""
    match = re.search(r"\s#", line)
    return line[: match.start()] if match else line


def parse_requirements_file(
    path: Path,
    *,
    file_path: str,
    group: DependencyGroup = DependencyGroup.MAIN,
    _visited: frozenset[Path] | None = None,
) -> list[DependencyRef]:
    """Parse one requirements-style file, following -r/-c includes.

    `_visited` guards against include cycles (PLAN.md edge case 2) — it is
    an internal recursion parameter, not part of the public contract.
    """
    visited = _visited or frozenset()
    resolved = path.resolve()
    if resolved in visited:
        logger.warning("Include cycle detected at %s; skipping", path)
        return []
    visited = visited | {resolved}

    refs: list[DependencyRef] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        logger.warning("Could not read %s", path, exc_info=True)
        return []

    # An --index-url / --extra-index-url line applies to the requirements
    # that follow it in the same file, so it is tracked as we go rather
    # than looked up afterwards. This is a real supply-chain signal: a
    # dependency pulled from a private or third-party index is a
    # materially different fact from one pulled from PyPI.
    current_index_url: str | None = None

    for line_number, raw_line in enumerate(lines, start=1):
        line = _strip_comment(raw_line).strip()
        if not line:
            continue

        index_match = _INDEX_URL_RE.match(line)
        if index_match:
            current_index_url = index_match.group(1).strip()
            continue

        include_match = _INCLUDE_RE.match(line)
        if include_match:
            included_path = (path.parent / include_match.group(2).strip()).resolve()
            included_group = (
                DependencyGroup.CONSTRAINTS
                if include_match.group(1).lower().startswith("c")
                else group
            )
            if included_path.is_file():
                refs.extend(
                    parse_requirements_file(
                        included_path,
                        file_path=file_path,
                        group=included_group,
                        _visited=visited,
                    )
                )
            continue

        editable_match = _EDITABLE_RE.match(line)
        if editable_match:
            egg_match = _EGG_NAME_RE.search(editable_match.group(2))
            if not egg_match:
                continue  # e.g. "-e ." — no matchable name (PLAN.md edge case 3)
            name = egg_match.group(1)
            editable_target = editable_match.group(2).strip()
            vcs_url, vcs_ref = split_vcs_url(editable_target)
            refs.append(
                DependencyRef(
                    name=name,
                    raw_declaration=raw_line.strip(),
                    version_spec=editable_target,
                    version_spec_kind=classify_version_spec(editable_target, Ecosystem.PYPI),
                    version_source=VersionSource.DECLARED,
                    ecosystem=Ecosystem.PYPI,
                    dependency_group=group,
                    is_direct=True,
                    file_path=file_path,
                    line_number=line_number,
                    declared_index_url=current_index_url,
                    vcs_url=vcs_url,
                    vcs_ref=vcs_ref,
                    local_path=None if vcs_url else editable_target,
                )
            )
            continue

        if line.startswith("-"):
            continue  # other pip flags (--index-url, --hash, etc.) — not a dependency

        req_part, marker = split_environment_marker(line)
        if not req_part:
            continue

        name, version_spec = split_pep508_name_and_specifier(req_part)
        name, extras = strip_extras(name)
        if not name:
            continue

        vcs_url, vcs_ref = split_vcs_url(version_spec)
        refs.append(
            DependencyRef(
                name=name,
                raw_declaration=raw_line.strip(),
                version_spec=version_spec,
                version_spec_kind=classify_version_spec(version_spec, Ecosystem.PYPI),
                version_source=VersionSource.DECLARED,
                ecosystem=Ecosystem.PYPI,
                dependency_group=group,
                is_direct=True,
                file_path=file_path,
                extras=extras,
                environment_marker=marker,
                version_constraints=split_version_constraints(version_spec),
                line_number=line_number,
                declared_index_url=current_index_url,
                vcs_url=vcs_url,
                vcs_ref=vcs_ref,
            )
        )

    return refs


def parse(path: Path, *, file_path: str, kind: str) -> list[DependencyRef]:
    """Entry point used by discovery/orchestration."""
    group = (
        DependencyGroup.CONSTRAINTS
        if kind == "python_constraints"
        else _group_from_filename(path.name)
    )
    return parse_requirements_file(path, file_path=file_path, group=group)


def _group_from_filename(filename: str) -> DependencyGroup:
    lower = filename.lower()
    if "dev" in lower or "test" in lower:
        return DependencyGroup.DEV
    return DependencyGroup.MAIN
