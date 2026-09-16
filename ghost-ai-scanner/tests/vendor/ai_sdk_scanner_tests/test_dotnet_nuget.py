"""*.csproj, packages.config, Directory.Packages.props. No real .NET
project exists on this machine — verified only against synthetic fixtures."""

from __future__ import annotations

from ai_sdk_scanner.models import DependencyGroup, VersionSpecKind
from ai_sdk_scanner.parsers.dotnet_nuget import (
    parse_central_package_versions,
    parse_packages_config,
    parse_project_file,
)


def test_package_reference_attribute_form(tmp_path):
    path = tmp_path / "app.csproj"
    path.write_text(
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        '  <ItemGroup>\n'
        '    <PackageReference Include="OpenAI" Version="2.0.0" />\n'
        '  </ItemGroup>\n'
        '</Project>\n',
        encoding="utf-8",
    )
    refs = parse_project_file(path, file_path="app.csproj")
    assert len(refs) == 1
    assert refs[0].name == "OpenAI"
    assert refs[0].version_spec == "2.0.0"
    assert refs[0].dependency_group == DependencyGroup.MAIN


def test_package_reference_nested_version_element(tmp_path):
    path = tmp_path / "app.csproj"
    path.write_text(
        '<Project><ItemGroup>\n'
        '  <PackageReference Include="Newtonsoft.Json">\n'
        '    <Version>13.0.1</Version>\n'
        '  </PackageReference>\n'
        '</ItemGroup></Project>\n',
        encoding="utf-8",
    )
    refs = parse_project_file(path, file_path="app.csproj")
    assert refs[0].version_spec == "13.0.1"


def test_private_assets_all_is_dev_group(tmp_path):
    path = tmp_path / "app.csproj"
    path.write_text(
        '<Project><ItemGroup>\n'
        '  <PackageReference Include="StyleCop.Analyzers" Version="1.2.0" PrivateAssets="All" />\n'
        '</ItemGroup></Project>\n',
        encoding="utf-8",
    )
    refs = parse_project_file(path, file_path="app.csproj")
    assert refs[0].dependency_group == DependencyGroup.DEV


def test_bare_version_is_a_minimum_not_a_pin(tmp_path):
    # NuGet convention: "2.0.0" alone means ">= 2.0.0" -- classifying it
    # PINNED would overclaim.
    path = tmp_path / "app.csproj"
    path.write_text(
        '<Project><ItemGroup><PackageReference Include="OpenAI" Version="2.0.0" />'
        '</ItemGroup></Project>\n',
        encoding="utf-8",
    )
    refs = parse_project_file(path, file_path="app.csproj")
    assert refs[0].version_spec_kind == VersionSpecKind.RANGE


def test_bracket_exact_version_is_pinned(tmp_path):
    path = tmp_path / "app.csproj"
    path.write_text(
        '<Project><ItemGroup><PackageReference Include="OpenAI" Version="[2.0.0]" />'
        '</ItemGroup></Project>\n',
        encoding="utf-8",
    )
    refs = parse_project_file(path, file_path="app.csproj")
    assert refs[0].version_spec_kind == VersionSpecKind.PINNED


def test_fsproj_and_vbproj_use_the_same_parser(tmp_path):
    for ext in ("fsproj", "vbproj"):
        path = tmp_path / f"app.{ext}"
        path.write_text(
            '<Project><ItemGroup><PackageReference Include="OpenAI" Version="2.0.0" />'
            '</ItemGroup></Project>\n',
            encoding="utf-8",
        )
        refs = parse_project_file(path, file_path=f"app.{ext}")
        assert refs[0].name == "OpenAI"


def test_packages_config(tmp_path):
    path = tmp_path / "packages.config"
    path.write_text(
        '<?xml version="1.0"?>\n<packages>\n'
        '  <package id="OpenAI" version="2.0.0" targetFramework="net472" />\n'
        '  <package id="NUnit" version="3.13.0" developmentDependency="true" />\n'
        "</packages>\n",
        encoding="utf-8",
    )
    refs = parse_packages_config(path, file_path="packages.config")
    by_name = {r.name: r for r in refs}
    assert by_name["OpenAI"].dependency_group == DependencyGroup.MAIN
    assert by_name["NUnit"].dependency_group == DependencyGroup.DEV


def test_central_package_versions_are_constraints_group(tmp_path):
    path = tmp_path / "Directory.Packages.props"
    path.write_text(
        '<Project>\n  <ItemGroup>\n'
        '    <PackageVersion Include="OpenAI" Version="2.0.0" />\n'
        '  </ItemGroup>\n</Project>\n',
        encoding="utf-8",
    )
    refs = parse_central_package_versions(path, file_path="Directory.Packages.props")
    assert refs[0].dependency_group == DependencyGroup.CONSTRAINTS


def test_malformed_xml_returns_empty(tmp_path):
    path = tmp_path / "app.csproj"
    path.write_text("<Project><Unclosed>", encoding="utf-8")
    assert parse_project_file(path, file_path="app.csproj") == []
