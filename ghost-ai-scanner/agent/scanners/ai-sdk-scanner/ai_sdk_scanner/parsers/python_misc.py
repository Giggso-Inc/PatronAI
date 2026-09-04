"""Pipfile, setup.cfg, and environment.yml. PLAN.md sections 4.1, 4.3.

`environment.yml` is real YAML, but PLAN.md section 3.4 (decision 2) rules
out a YAML dependency for this project. `_parse_environment_yml` is a
narrow, purpose-built line parser that handles the one shape this file
actually takes in practice — a flat `dependencies:` list plus one nested
`pip:` block — and nothing more. See that section for the honest limits.
"""

from __future__ import annotations

import configparser
import logging
import tomllib
from pathlib import Path
from typing import Any

from ai_sdk_scanner.models import (
    DependencyGroup,
    DependencyRef,
    Ecosystem,
    VersionSource,
    VersionSpecKind,
)
from ai_sdk_scanner.normalize import (
    split_pep508_name_and_specifier,
    split_vcs_url,
    split_version_constraints,
    strip_extras,
)
from ai_sdk_scanner.parsers.base import classify_version_spec, find_line_number

logger = logging.getLogger(__name__)


def _make_ref(
    name: str,
    version_spec: str,
    *,
    group: DependencyGroup,
    file_path: str,
    raw: str,
    version_spec_kind: VersionSpecKind | None = None,
    lines: list[str] | None = None,
    is_optional: bool = False,
) -> DependencyRef | None:
    name, extras = strip_extras(name)
    if not name:
        return None
    kind = version_spec_kind or classify_version_spec(version_spec, Ecosystem.PYPI)
    vcs_url, vcs_ref = split_vcs_url(version_spec)
    return DependencyRef(
        name=name,
        raw_declaration=raw,
        version_spec=version_spec,
        version_spec_kind=kind,
        version_source=VersionSource.DECLARED,
        ecosystem=Ecosystem.PYPI,
        dependency_group=group,
        is_direct=True,
        file_path=file_path,
        extras=extras,
        version_constraints=split_version_constraints(version_spec),
        line_number=find_line_number(lines, name) if lines else None,
        is_optional=is_optional,
        vcs_url=vcs_url,
        vcs_ref=vcs_ref,
    )


# ---------------------------------------------------------------------------
# Pipfile — TOML: [packages], [dev-packages]
# ---------------------------------------------------------------------------

def parse_pipfile(path: Path, *, file_path: str) -> list[DependencyRef]:
    try:
        text = path.read_text(encoding="utf-8")
        data = tomllib.loads(text)
    except (OSError, tomllib.TOMLDecodeError):
        logger.warning("Could not parse %s", path, exc_info=True)
        return []

    lines = text.splitlines()
    refs: list[DependencyRef] = []
    refs.extend(_pipfile_table(data.get("packages", {}), DependencyGroup.MAIN, file_path, lines))
    refs.extend(_pipfile_table(data.get("dev-packages", {}), DependencyGroup.DEV, file_path, lines))
    return refs


def _pipfile_table(
    table: dict[str, Any], group: DependencyGroup, file_path: str, lines: list[str]
) -> list[DependencyRef]:
    refs: list[DependencyRef] = []
    for name, spec in table.items():
        if isinstance(spec, str):
            version_spec = "" if spec == "*" else spec
        elif isinstance(spec, dict):
            version_spec = spec.get("version", "")
            version_spec = "" if version_spec == "*" else version_spec
        else:
            version_spec = ""
        ref = _make_ref(
            name, version_spec, group=group, file_path=file_path,
            raw=f"{name} = {spec!r}", lines=lines,
        )
        if ref:
            refs.append(ref)
    return refs


# ---------------------------------------------------------------------------
# setup.cfg — INI: [options] install_requires, [options.extras_require]
# ---------------------------------------------------------------------------

def parse_setup_cfg(path: Path, *, file_path: str) -> list[DependencyRef]:
    parser = configparser.ConfigParser()
    try:
        text = path.read_text(encoding="utf-8")
        parser.read_string(text)
    except (OSError, configparser.Error):
        logger.warning("Could not parse %s", path, exc_info=True)
        return []

    lines = text.splitlines()
    refs: list[DependencyRef] = []
    if parser.has_section("options"):
        install_requires = parser.get("options", "install_requires", fallback="")
        refs.extend(_setup_cfg_lines(install_requires, DependencyGroup.MAIN, file_path, lines))

    if parser.has_section("options.extras_require"):
        for _extra_name, value in parser.items("options.extras_require"):
            refs.extend(
                _setup_cfg_lines(value, DependencyGroup.OPTIONAL, file_path, lines)
            )

    return refs


def _setup_cfg_lines(
    block: str, group: DependencyGroup, file_path: str, lines: list[str]
) -> list[DependencyRef]:
    refs: list[DependencyRef] = []
    for line in block.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, version_spec = split_pep508_name_and_specifier(line)
        ref = _make_ref(
            name, version_spec, group=group, file_path=file_path, raw=line, lines=lines
        )
        if ref:
            refs.append(ref)
    return refs


# ---------------------------------------------------------------------------
# environment.yml — hand-rolled, deliberately narrow (see module docstring)
# ---------------------------------------------------------------------------

def _leading_spaces(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def parse_environment_yml(path: Path, *, file_path: str) -> list[DependencyRef]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        logger.warning("Could not read %s", path, exc_info=True)
        return []

    lines = text.splitlines()
    refs: list[DependencyRef] = []

    deps_indent: int | None = None
    pip_indent: int | None = None
    in_pip = False

    for line in lines:
        if not line.strip():
            continue
        indent = _leading_spaces(line)
        stripped = line.strip()

        if deps_indent is None:
            if stripped.rstrip(":") == "dependencies" or stripped == "dependencies:":
                deps_indent = indent
            continue

        if indent <= deps_indent and not stripped.startswith("-"):
            break  # left the dependencies block entirely

        if not stripped.startswith("-"):
            continue

        item = stripped[1:].strip()

        if in_pip and indent <= pip_indent:  # type: ignore[operator]
            in_pip = False  # a sibling list item at/above the pip: line's own indent

        if item.rstrip(":") == "pip" and item.endswith(":"):
            in_pip = True
            pip_indent = indent
            continue

        name, version_spec = _split_conda_or_pip_entry(item, in_pip=in_pip)
        if not name:
            continue
        kind = _conda_version_kind(version_spec) if not in_pip else classify_version_spec(
            version_spec, Ecosystem.PYPI
        )
        ref = _make_ref(
            name, version_spec, group=DependencyGroup.MAIN, file_path=file_path,
            raw=stripped, version_spec_kind=kind, lines=lines,
        )
        if ref:
            refs.append(ref)

    return refs


def _split_conda_or_pip_entry(item: str, *, in_pip: bool) -> tuple[str, str]:
    item = item.strip().strip('"').strip("'")
    if in_pip:
        name, version_spec = split_pep508_name_and_specifier(item)
        return name, version_spec
    # Conda shorthand: `name=version` (single '=', PLAN.md edge case 11).
    if "=" in item:
        name, _, version = item.partition("=")
        return name.strip(), version.strip()
    return item.strip(), ""


def _conda_version_kind(version_spec: str) -> VersionSpecKind:
    return VersionSpecKind.PINNED if version_spec else VersionSpecKind.UNPINNED
