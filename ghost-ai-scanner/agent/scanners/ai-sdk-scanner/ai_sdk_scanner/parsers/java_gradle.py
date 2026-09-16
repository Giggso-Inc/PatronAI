"""build.gradle / build.gradle.kts — Gradle. Verified only against
synthetic fixtures (no real Gradle project exists on the development
machine at the time of writing).

Gradle build files are Groovy or Kotlin CODE, not data — the same class
of problem as `setup.py` (PLAN.md section 4.3). Unlike `setup.py`, the
common dependency-declaration shapes are regular enough to extract with a
line-oriented, best-effort parser, so this is attempted rather than
marked wholly unparsed. What it can read:

    implementation 'group:artifact:1.0'
    implementation("group:artifact:1.0")
    implementation group: 'g', name: 'a', version: '1.0'
    testImplementation "group:artifact:1.0"

What it CANNOT read, and silently produces no record for (a real,
named limitation, not a bug): version-catalog references
(`implementation(libs.some.lib)`), variables/property interpolation
(`"$group:$artifact:$version"`), and anything built by a function call
or loop rather than written as a literal.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ai_sdk_scanner.models import DependencyGroup, DependencyRef, Ecosystem, VersionSource
from ai_sdk_scanner.parsers.base import classify_version_spec

logger = logging.getLogger(__name__)

_CONFIG_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9]*)\s*[(\s]")
_COORD_STRING_RE = re.compile(r"""['"]([^:'"\s]+):([^:'"\s]+):([^'"\s]+)['"]""")
_NAMED_GROUP_RE = re.compile(r"""\bgroup\s*:\s*['"]([^'"]+)['"]""")
_NAMED_NAME_RE = re.compile(r"""\bname\s*:\s*['"]([^'"]+)['"]""")
_NAMED_VERSION_RE = re.compile(r"""\bversion\s*:\s*['"]([^'"]+)['"]""")

_RECOGNIZED_CONFIGS = frozenset({
    "implementation", "api", "compileonly", "compileonlyapi", "runtimeonly",
    "testimplementation", "testcompileonly", "testruntimeonly",
    "androidtestimplementation",
    "annotationprocessor", "kapt", "kaptandroidtest", "ksp",
    "debugimplementation", "releaseimplementation",
    "classpath",
})


def _group_for_config(config_lower: str) -> tuple[DependencyGroup, bool]:
    """(dependency_group, is_optional)."""
    if config_lower.startswith("test") or config_lower.startswith("androidtest"):
        return DependencyGroup.DEV, False
    if config_lower in ("annotationprocessor", "kapt", "kaptandroidtest", "ksp"):
        return DependencyGroup.DEV, False
    if config_lower in ("compileonly", "compileonlyapi"):
        return DependencyGroup.OPTIONAL, True
    return DependencyGroup.MAIN, False


def parse(path: Path, *, file_path: str) -> list[DependencyRef]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        logger.warning("Could not read %s", path, exc_info=True)
        return []

    refs: list[DependencyRef] = []
    for line_number, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("//"):
            continue

        config_match = _CONFIG_RE.match(raw_line)
        if not config_match:
            continue
        config = config_match.group(1)
        if config.lower() not in _RECOGNIZED_CONFIGS:
            continue

        group_id = artifact_id = version = None

        coord_match = _COORD_STRING_RE.search(raw_line)
        if coord_match:
            group_id, artifact_id, version = coord_match.groups()
        else:
            g = _NAMED_GROUP_RE.search(raw_line)
            n = _NAMED_NAME_RE.search(raw_line)
            v = _NAMED_VERSION_RE.search(raw_line)
            if g and n:
                group_id, artifact_id = g.group(1), n.group(1)
                version = v.group(1) if v else ""

        if not group_id or not artifact_id:
            continue  # version catalog ref, interpolated string, etc. -- skip

        dep_group, is_optional = _group_for_config(config.lower())
        name = f"{group_id}:{artifact_id}"
        version = version or ""
        refs.append(
            DependencyRef(
                name=name,
                raw_declaration=stripped,
                version_spec=version,
                version_spec_kind=classify_version_spec(version, Ecosystem.MAVEN),
                version_source=VersionSource.DECLARED,
                ecosystem=Ecosystem.MAVEN,
                dependency_group=dep_group,
                is_direct=True,
                file_path=file_path,
                line_number=line_number,
                is_optional=is_optional,
            )
        )

    return refs
