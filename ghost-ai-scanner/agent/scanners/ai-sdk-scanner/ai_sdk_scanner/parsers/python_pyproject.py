"""pyproject.toml: PEP 621, Poetry, and PDM/uv dev groups. PLAN.md section 4.1.

Three dependency-declaration styles can coexist in one file. Each is
independent — a project could theoretically have both `[project]` PEP 621
deps and legacy `[tool.poetry.dependencies]`, and both are read.
"""

from __future__ import annotations

import logging
import tomllib
from dataclasses import replace
from pathlib import Path
from typing import Any

from ai_sdk_scanner.models import DependencyGroup, DependencyRef, Ecosystem, VersionSource
from ai_sdk_scanner.normalize import (
    split_environment_marker,
    split_pep508_name_and_specifier,
    split_vcs_url,
    split_version_constraints,
    strip_extras,
)
from ai_sdk_scanner.parsers.base import classify_version_spec, find_line_number

logger = logging.getLogger(__name__)

# PLAN.md edge case 8: Poetry's `python = "^3.11"` is a runtime constraint,
# not a package — every Poetry dependency table has this key and it must
# never be emitted as a dependency.
_POETRY_PYTHON_KEY = "python"


def parse(path: Path, *, file_path: str) -> list[DependencyRef]:
    try:
        text = path.read_text(encoding="utf-8")
        data = tomllib.loads(text)
    except (OSError, tomllib.TOMLDecodeError):
        logger.warning("Could not parse %s", path, exc_info=True)
        return []

    lines = text.splitlines()
    refs: list[DependencyRef] = []
    refs.extend(_parse_pep621(data, file_path, lines))
    refs.extend(_parse_poetry(data, file_path, lines))
    refs.extend(_parse_pdm_dev(data, file_path, lines))
    refs.extend(_parse_uv_dev(data, file_path, lines))
    return refs


def _make_ref(
    name: str,
    version_spec: str,
    *,
    group: DependencyGroup,
    file_path: str,
    raw: str,
    lines: list[str],
    extras: tuple[str, ...] = (),
    marker: str | None = None,
    is_optional: bool = False,
    vcs_url: str | None = None,
    vcs_ref: str | None = None,
    local_path: str | None = None,
) -> DependencyRef | None:
    name, parsed_extras = strip_extras(name)
    if not name:
        return None
    if vcs_url is None and vcs_ref is None:
        vcs_url, vcs_ref = split_vcs_url(version_spec)
    return DependencyRef(
        name=name,
        raw_declaration=raw,
        version_spec=version_spec,
        version_spec_kind=classify_version_spec(version_spec, Ecosystem.PYPI),
        version_source=VersionSource.DECLARED,
        ecosystem=Ecosystem.PYPI,
        dependency_group=group,
        is_direct=True,
        file_path=file_path,
        extras=extras or parsed_extras,
        environment_marker=marker,
        version_constraints=split_version_constraints(version_spec),
        line_number=find_line_number(lines, name),
        is_optional=is_optional,
        vcs_url=vcs_url,
        vcs_ref=vcs_ref,
        local_path=local_path,
    )


def _parse_pep621_string(
    dep_str: str, *, group: DependencyGroup, file_path: str, lines: list[str]
) -> DependencyRef | None:
    req_part, marker = split_environment_marker(dep_str)
    if not req_part:
        return None
    name, version_spec = split_pep508_name_and_specifier(req_part)
    return _make_ref(
        name, version_spec, group=group, file_path=file_path, raw=dep_str,
        lines=lines, marker=marker,
    )


def _parse_pep621(
    data: dict[str, Any], file_path: str, lines: list[str]
) -> list[DependencyRef]:
    project = data.get("project", {})
    if not isinstance(project, dict):
        return []

    refs: list[DependencyRef] = []
    for dep_str in project.get("dependencies", []) or []:
        ref = _parse_pep621_string(
            dep_str, group=DependencyGroup.MAIN, file_path=file_path, lines=lines
        )
        if ref:
            refs.append(ref)

    optional = project.get("optional-dependencies", {}) or {}
    for deps in optional.values():
        for dep_str in deps:
            ref = _parse_pep621_string(
                dep_str, group=DependencyGroup.OPTIONAL, file_path=file_path, lines=lines
            )
            if ref:
                refs.append(ref)

    # PEP 735 dependency groups: [dependency-groups]
    dep_groups = data.get("dependency-groups", {}) or {}
    for deps in dep_groups.values():
        for dep_str in deps:
            if not isinstance(dep_str, str):
                continue  # skip {"include-group": "..."} entries
            ref = _parse_pep621_string(
                dep_str, group=DependencyGroup.DEV, file_path=file_path, lines=lines
            )
            if ref:
                refs.append(ref)

    return refs


def _poetry_spec_to_string(spec: Any) -> str:
    """Poetry allows `name = "^1.0"` or `name = {version = "^1.0", ...}`."""
    if isinstance(spec, str):
        return spec
    if isinstance(spec, dict):
        version = spec.get("version")
        return version if isinstance(version, str) else ""
    return ""


def _parse_poetry_table(
    table: dict[str, Any], *, group: DependencyGroup, file_path: str, lines: list[str]
) -> list[DependencyRef]:
    refs: list[DependencyRef] = []
    for name, spec in table.items():
        if name == _POETRY_PYTHON_KEY:
            continue  # edge case 8
        version_spec = _poetry_spec_to_string(spec)
        raw = f"{name} = {spec!r}"

        # PLAN.md edge case 9: table-form entries may mark `optional = true`.
        # The table form also carries the package's actual SOURCE, which the
        # plain version string cannot express: a git URL + ref, a local path,
        # or a named alternate index.
        entry_group = group
        is_optional = False
        vcs_url: str | None = None
        vcs_ref: str | None = None
        local_path: str | None = None
        index_url: str | None = None

        if isinstance(spec, dict):
            if spec.get("optional") is True:
                entry_group = DependencyGroup.OPTIONAL
                is_optional = True
            git_url = spec.get("git")
            if isinstance(git_url, str):
                vcs_url = git_url
                # Poetry expresses the ref as one of three mutually
                # exclusive keys; first present wins.
                for ref_key in ("rev", "tag", "branch"):
                    candidate = spec.get(ref_key)
                    if isinstance(candidate, str):
                        vcs_ref = candidate
                        break
            path_value = spec.get("path")
            if isinstance(path_value, str):
                local_path = path_value
            source_value = spec.get("source")
            if isinstance(source_value, str):
                index_url = source_value

        ref = _make_ref(
            name, version_spec, group=entry_group, file_path=file_path, raw=raw,
            lines=lines, is_optional=is_optional, vcs_url=vcs_url, vcs_ref=vcs_ref,
            local_path=local_path,
        )
        if ref and index_url:
            ref = replace(ref, declared_index_url=index_url)
        if ref:
            refs.append(ref)
    return refs


def _parse_poetry(
    data: dict[str, Any], file_path: str, lines: list[str]
) -> list[DependencyRef]:
    poetry = data.get("tool", {}).get("poetry", {})
    if not isinstance(poetry, dict):
        return []

    refs: list[DependencyRef] = []
    main_deps = poetry.get("dependencies", {}) or {}
    refs.extend(
        _parse_poetry_table(
            main_deps, group=DependencyGroup.MAIN, file_path=file_path, lines=lines
        )
    )

    # Legacy Poetry <1.2 syntax.
    legacy_dev = poetry.get("dev-dependencies", {}) or {}
    refs.extend(
        _parse_poetry_table(
            legacy_dev, group=DependencyGroup.DEV, file_path=file_path, lines=lines
        )
    )

    # Modern Poetry >=1.2 dependency groups: [tool.poetry.group.<name>.dependencies]
    groups = poetry.get("group", {}) or {}
    for group_name, group_table in groups.items():
        deps = group_table.get("dependencies", {}) if isinstance(group_table, dict) else {}
        dep_group = DependencyGroup.MAIN if group_name == "main" else DependencyGroup.DEV
        refs.extend(
            _parse_poetry_table(deps, group=dep_group, file_path=file_path, lines=lines)
        )

    return refs


def _parse_pdm_dev(
    data: dict[str, Any], file_path: str, lines: list[str]
) -> list[DependencyRef]:
    pdm_dev = data.get("tool", {}).get("pdm", {}).get("dev-dependencies", {})
    if not isinstance(pdm_dev, dict):
        return []
    refs: list[DependencyRef] = []
    for deps in pdm_dev.values():
        for dep_str in deps or []:
            ref = _parse_pep621_string(
                dep_str, group=DependencyGroup.DEV, file_path=file_path, lines=lines
            )
            if ref:
                refs.append(ref)
    return refs


def _parse_uv_dev(
    data: dict[str, Any], file_path: str, lines: list[str]
) -> list[DependencyRef]:
    uv = data.get("tool", {}).get("uv", {})
    if not isinstance(uv, dict):
        return []
    refs: list[DependencyRef] = []
    for dep_str in uv.get("dev-dependencies", []) or []:
        ref = _parse_pep621_string(
            dep_str, group=DependencyGroup.DEV, file_path=file_path, lines=lines
        )
        if ref:
            refs.append(ref)
    return refs
