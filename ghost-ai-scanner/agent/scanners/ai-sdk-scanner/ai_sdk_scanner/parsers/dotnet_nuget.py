"""*.csproj/*.fsproj/*.vbproj, packages.config, Directory.Packages.props —
NuGet. Verified only against synthetic fixtures (no real .NET project
exists on the development machine at the time of writing).

Three real formats share this module because they all boil down to the
same XML shape (`<SomeTag Include="pkg" Version="1.0" />`):

- SDK-style `.csproj`/`.fsproj`/`.vbproj`: `<PackageReference>`, version as
  either an attribute or a nested `<Version>` element.
- Legacy `packages.config`: `<package id="..." version="..." />`.
- Central Package Management's `Directory.Packages.props`:
  `<PackageVersion Include="..." Version="..." />` — treated as
  CONSTRAINTS, the same precedent as pip's constraints.txt, since it
  states an allowed version without itself being a direct reference.
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from pathlib import Path

from ai_sdk_scanner.models import DependencyGroup, DependencyRef, Ecosystem, VersionSource
from ai_sdk_scanner.parsers.base import classify_version_spec

logger = logging.getLogger(__name__)


def _local_tag(elem: ET.Element) -> str:
    return elem.tag.rsplit("}", 1)[-1]


def _find_line(lines: list[str], name: str) -> int | None:
    needle = name.lower()
    for i, line in enumerate(lines, start=1):
        if needle in line.lower():
            return i
    return None


def _make_ref(
    name: str, version: str, *, group: DependencyGroup, file_path: str,
    raw: str, line_number: int | None, is_optional: bool = False,
) -> DependencyRef:
    return DependencyRef(
        name=name,
        raw_declaration=raw,
        version_spec=version,
        version_spec_kind=classify_version_spec(version, Ecosystem.NUGET),
        version_source=VersionSource.DECLARED,
        ecosystem=Ecosystem.NUGET,
        dependency_group=group,
        is_direct=True,
        file_path=file_path,
        line_number=line_number,
        is_optional=is_optional,
    )


def _parse_xml(path: Path) -> tuple[ET.Element, list[str]] | None:
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        root = ET.fromstring(text)
    except (OSError, ET.ParseError):
        logger.warning("Could not parse %s", path, exc_info=True)
        return None
    return root, text.splitlines()


def parse_project_file(path: Path, *, file_path: str) -> list[DependencyRef]:
    """*.csproj / *.fsproj / *.vbproj: <PackageReference> elements."""
    parsed = _parse_xml(path)
    if parsed is None:
        return []
    root, lines = parsed

    refs: list[DependencyRef] = []
    for elem in root.iter():
        if _local_tag(elem) != "PackageReference":
            continue
        name = elem.get("Include") or elem.get("Update")
        if not name:
            continue
        version = elem.get("Version") or ""
        if not version:
            for child in elem:
                if _local_tag(child) == "Version" and child.text:
                    version = child.text.strip()
                    break

        private_assets = (elem.get("PrivateAssets") or "").lower()
        group = (
            DependencyGroup.DEV
            if private_assets in ("all", "analyzers")
            else DependencyGroup.MAIN
        )

        refs.append(
            _make_ref(
                name, version, group=group, file_path=file_path,
                raw=f'Include="{name}" Version="{version}"',
                line_number=_find_line(lines, name),
            )
        )
    return refs


def parse_packages_config(path: Path, *, file_path: str) -> list[DependencyRef]:
    """Legacy packages.config: <package id="..." version="..." />."""
    parsed = _parse_xml(path)
    if parsed is None:
        return []
    root, lines = parsed

    refs: list[DependencyRef] = []
    for elem in root.iter():
        if _local_tag(elem) != "package":
            continue
        name = elem.get("id")
        if not name:
            continue
        version = elem.get("version") or ""
        is_dev = (elem.get("developmentDependency") or "").lower() == "true"
        refs.append(
            _make_ref(
                name, version,
                group=DependencyGroup.DEV if is_dev else DependencyGroup.MAIN,
                file_path=file_path,
                raw=f'id="{name}" version="{version}"',
                line_number=_find_line(lines, name),
            )
        )
    return refs


def parse_central_package_versions(path: Path, *, file_path: str) -> list[DependencyRef]:
    """Directory.Packages.props: <PackageVersion Include="..." Version="..." />."""
    parsed = _parse_xml(path)
    if parsed is None:
        return []
    root, lines = parsed

    refs: list[DependencyRef] = []
    for elem in root.iter():
        if _local_tag(elem) != "PackageVersion":
            continue
        name = elem.get("Include")
        if not name:
            continue
        version = elem.get("Version") or ""
        refs.append(
            _make_ref(
                name, version, group=DependencyGroup.CONSTRAINTS, file_path=file_path,
                raw=f'Include="{name}" Version="{version}"',
                line_number=_find_line(lines, name),
            )
        )
    return refs
