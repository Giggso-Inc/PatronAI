"""package.json. PLAN.md section 4.1.

dependencies / devDependencies / peerDependencies / optionalDependencies —
each becomes its own DependencyGroup so the same library declared in two
groups produces two distinct, honest rows (PLAN.md edge case 6).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from ai_sdk_scanner.models import DependencyGroup, DependencyRef, Ecosystem, VersionSource
from ai_sdk_scanner.normalize import split_vcs_url
from ai_sdk_scanner.parsers.base import classify_version_spec, find_line_number

logger = logging.getLogger(__name__)

_SECTION_GROUPS = (
    ("dependencies", DependencyGroup.MAIN),
    ("devDependencies", DependencyGroup.DEV),
    ("peerDependencies", DependencyGroup.PEER),
    ("optionalDependencies", DependencyGroup.OPTIONAL),
)


def parse(path: Path, *, file_path: str) -> list[DependencyRef]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(text)
    except (OSError, json.JSONDecodeError):
        logger.warning("Could not parse %s", path, exc_info=True)
        return []
    if not isinstance(data, dict):
        return []

    lines = text.splitlines()
    # An npm registry override in package.json applies to the whole file.
    index_url = _publish_registry(data)

    refs: list[DependencyRef] = []
    for section, group in _SECTION_GROUPS:
        entries = data.get(section)
        if not isinstance(entries, dict):
            continue
        for name, version_spec in entries.items():
            if not isinstance(version_spec, str):
                continue
            vcs_url, vcs_ref = split_vcs_url(version_spec)
            refs.append(
                DependencyRef(
                    name=name,
                    raw_declaration=f'"{name}": "{version_spec}"',
                    version_spec=version_spec,
                    version_spec_kind=classify_version_spec(version_spec, Ecosystem.NPM),
                    version_source=VersionSource.DECLARED,
                    ecosystem=Ecosystem.NPM,
                    dependency_group=group,
                    is_direct=True,
                    file_path=file_path,
                    line_number=find_line_number(lines, name),
                    is_optional=section == "optionalDependencies",
                    declared_index_url=index_url,
                    vcs_url=vcs_url,
                    vcs_ref=vcs_ref,
                    local_path=(
                        version_spec if version_spec.startswith(("file:", "link:")) else None
                    ),
                )
            )
    return refs


def _publish_registry(data: dict[str, object]) -> str | None:
    """`publishConfig.registry`, when the package pins a non-default registry."""
    publish_config = data.get("publishConfig")
    if isinstance(publish_config, dict):
        registry = publish_config.get("registry")
        if isinstance(registry, str):
            return registry
    return None
