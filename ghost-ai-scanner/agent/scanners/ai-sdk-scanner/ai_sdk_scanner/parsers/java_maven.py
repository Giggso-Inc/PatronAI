"""pom.xml — Maven. Verified only against synthetic fixtures (no real
Maven project exists on the development machine at the time of writing).

Parses only `/project/dependencies` (direct) and
`/project/dependencyManagement/dependencies` (constraints). Deliberately
does NOT descend into `<profiles>` — a profile's dependencies are
conditionally activated and Maven's activation rules (JDK version, OS,
property presence, explicit `-P` flag) are not evaluated here. Declaring
those as unconditional dependencies would overclaim; omitting them is the
honest simplification, same spirit as PLAN.md's `setup.py` exclusion.

`${property}` version placeholders are NOT resolved — Maven's property
inheritance spans parent POMs this parser never fetches. The raw
`${...}` string is kept verbatim in `dependency_version`, classified
`UNPINNED` (see `parsers/base.py`), rather than guessed at.
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from pathlib import Path

from ai_sdk_scanner.models import DependencyGroup, DependencyRef, Ecosystem, VersionSource
from ai_sdk_scanner.parsers.base import classify_version_spec

logger = logging.getLogger(__name__)

_SCOPE_TO_GROUP = {
    "test": DependencyGroup.DEV,
    "provided": DependencyGroup.OPTIONAL,
    "system": DependencyGroup.OPTIONAL,
    # "compile" and "runtime" (and no scope at all, which defaults to
    # "compile") both map to MAIN via the .get() fallback below.
}


def _local_tag(elem: ET.Element) -> str:
    """Strip the namespace off an ElementTree tag: '{ns}dependency' -> 'dependency'."""
    return elem.tag.rsplit("}", 1)[-1]


def _child_text(dep_elem: ET.Element, name: str) -> str | None:
    for child in dep_elem:
        if _local_tag(child) == name and child.text:
            return child.text.strip()
    return None


def _find_line_for_dependency(lines: list[str], group_id: str, artifact_id: str) -> int | None:
    """Best-effort: find the `<artifactId>` line for this exact coordinate."""
    target = f"<artifactId>{artifact_id}</artifactId>"
    for i, line in enumerate(lines, start=1):
        if target in line:
            return i
    return None


def _parse_dependencies_block(
    deps_elem: ET.Element,
    *,
    file_path: str,
    lines: list[str],
    group_override: DependencyGroup | None,
) -> list[DependencyRef]:
    refs: list[DependencyRef] = []
    for dep in deps_elem:
        if _local_tag(dep) != "dependency":
            continue
        group_id = _child_text(dep, "groupId")
        artifact_id = _child_text(dep, "artifactId")
        if not group_id or not artifact_id:
            continue
        version = _child_text(dep, "version") or ""
        scope = _child_text(dep, "scope")
        optional = (_child_text(dep, "optional") or "").lower() == "true"

        group = group_override or _SCOPE_TO_GROUP.get(scope or "", DependencyGroup.MAIN)
        if optional and group == DependencyGroup.MAIN:
            group = DependencyGroup.OPTIONAL

        name = f"{group_id}:{artifact_id}"
        refs.append(
            DependencyRef(
                name=name,
                raw_declaration=f"{name}:{version}" if version else name,
                version_spec=version,
                version_spec_kind=classify_version_spec(version, Ecosystem.MAVEN),
                version_source=VersionSource.DECLARED,
                ecosystem=Ecosystem.MAVEN,
                dependency_group=group,
                is_direct=True,
                file_path=file_path,
                line_number=_find_line_for_dependency(lines, group_id, artifact_id),
                is_optional=optional,
            )
        )
    return refs


def parse(path: Path, *, file_path: str) -> list[DependencyRef]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        root = ET.fromstring(text)
    except (OSError, ET.ParseError):
        logger.warning("Could not parse %s", path, exc_info=True)
        return []

    lines = text.splitlines()
    refs: list[DependencyRef] = []

    for child in root:
        tag = _local_tag(child)
        if tag == "dependencies":
            refs.extend(
                _parse_dependencies_block(
                    child, file_path=file_path, lines=lines, group_override=None
                )
            )
        elif tag == "dependencyManagement":
            for grandchild in child:
                if _local_tag(grandchild) == "dependencies":
                    refs.extend(
                        _parse_dependencies_block(
                            grandchild, file_path=file_path, lines=lines,
                            group_override=DependencyGroup.CONSTRAINTS,
                        )
                    )

    return refs
