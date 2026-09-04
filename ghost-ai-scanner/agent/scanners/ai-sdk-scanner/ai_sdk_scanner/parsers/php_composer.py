"""composer.json — PHP/Packagist. Verified only against synthetic
fixtures (no real PHP project exists on the development machine at the
time of writing).

`require` and `require-dev`. Platform pseudo-packages (`php`, `ext-*`,
`lib-*`, `composer-plugin-api`) are excluded — they declare a runtime
requirement, not a Packagist package, the same reasoning as PLAN.md
section 11 edge case 8 excluding Poetry's `python = "^3.11"` key.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from ai_sdk_scanner.models import DependencyGroup, DependencyRef, Ecosystem, VersionSource
from ai_sdk_scanner.parsers.base import classify_version_spec, find_line_number

logger = logging.getLogger(__name__)

_SECTION_GROUPS = (
    ("require", DependencyGroup.MAIN),
    ("require-dev", DependencyGroup.DEV),
)


def _is_platform_package(name: str) -> bool:
    lower = name.lower()
    return (
        lower == "php"
        or lower.startswith("ext-")
        or lower.startswith("lib-")
        or lower == "composer-plugin-api"
        or lower == "composer-runtime-api"
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
    refs: list[DependencyRef] = []
    for section, group in _SECTION_GROUPS:
        entries = data.get(section)
        if not isinstance(entries, dict):
            continue
        for name, version_spec in entries.items():
            if _is_platform_package(name) or not isinstance(version_spec, str):
                continue
            refs.append(
                DependencyRef(
                    name=name,
                    raw_declaration=f'"{name}": "{version_spec}"',
                    version_spec=version_spec,
                    version_spec_kind=classify_version_spec(version_spec, Ecosystem.COMPOSER),
                    version_source=VersionSource.DECLARED,
                    ecosystem=Ecosystem.COMPOSER,
                    dependency_group=group,
                    is_direct=True,
                    file_path=file_path,
                    line_number=find_line_number(lines, name),
                )
            )
    return refs
