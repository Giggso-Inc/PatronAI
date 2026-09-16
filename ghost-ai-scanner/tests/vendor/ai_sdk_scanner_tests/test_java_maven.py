"""pom.xml. No real Maven project exists on this machine — verified only
against synthetic fixtures, per the explicit trade-off in java_maven.py."""

from __future__ import annotations

from ai_sdk_scanner.models import DependencyGroup, VersionSpecKind
from ai_sdk_scanner.parsers.java_maven import parse

_POM_HEADER = '<?xml version="1.0"?>\n<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
_POM_FOOTER = "\n</project>\n"


def _write_and_parse(tmp_path, body):
    path = tmp_path / "pom.xml"
    path.write_text(_POM_HEADER + body + _POM_FOOTER, encoding="utf-8")
    return parse(path, file_path="pom.xml")


def test_basic_dependency(tmp_path):
    refs = _write_and_parse(tmp_path, """
<dependencies>
  <dependency>
    <groupId>com.openai</groupId>
    <artifactId>openai-java</artifactId>
    <version>0.5.0</version>
  </dependency>
</dependencies>
""")
    assert len(refs) == 1
    r = refs[0]
    assert r.name == "com.openai:openai-java"
    assert r.version_spec == "0.5.0"
    assert r.version_spec_kind == VersionSpecKind.PINNED
    assert r.dependency_group == DependencyGroup.MAIN
    assert r.line_number is not None


def test_test_scope_is_dev_group(tmp_path):
    refs = _write_and_parse(tmp_path, """
<dependencies>
  <dependency>
    <groupId>org.junit.jupiter</groupId>
    <artifactId>junit-jupiter</artifactId>
    <version>5.10.0</version>
    <scope>test</scope>
  </dependency>
</dependencies>
""")
    assert refs[0].dependency_group == DependencyGroup.DEV


def test_provided_scope_is_optional(tmp_path):
    refs = _write_and_parse(tmp_path, """
<dependencies>
  <dependency>
    <groupId>javax.servlet</groupId>
    <artifactId>servlet-api</artifactId>
    <version>2.5</version>
    <scope>provided</scope>
  </dependency>
</dependencies>
""")
    assert refs[0].dependency_group == DependencyGroup.OPTIONAL


def test_dependency_management_is_constraints_group(tmp_path):
    refs = _write_and_parse(tmp_path, """
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson</groupId>
      <artifactId>jackson-bom</artifactId>
      <version>2.15.0</version>
    </dependency>
  </dependencies>
</dependencyManagement>
""")
    assert refs[0].dependency_group == DependencyGroup.CONSTRAINTS


def test_property_placeholder_version_is_unpinned_not_guessed(tmp_path):
    refs = _write_and_parse(tmp_path, """
<dependencies>
  <dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>${jackson.version}</version>
  </dependency>
</dependencies>
""")
    assert refs[0].version_spec == "${jackson.version}"  # kept verbatim
    assert refs[0].version_spec_kind == VersionSpecKind.UNPINNED


def test_maven_range_syntax(tmp_path):
    refs = _write_and_parse(tmp_path, """
<dependencies>
  <dependency>
    <groupId>com.example</groupId>
    <artifactId>lib</artifactId>
    <version>[1.0,2.0)</version>
  </dependency>
</dependencies>
""")
    assert refs[0].version_spec_kind == VersionSpecKind.RANGE


def test_malformed_xml_returns_empty_not_raise(tmp_path):
    path = tmp_path / "pom.xml"
    path.write_text("<project><unclosed>", encoding="utf-8")
    assert parse(path, file_path="pom.xml") == []


def test_profiles_dependencies_are_not_parsed(tmp_path):
    # Documented limitation: profile activation isn't evaluated, so
    # profile-scoped dependencies are correctly NOT emitted (not a bug).
    refs = _write_and_parse(tmp_path, """
<profiles>
  <profile>
    <id>extra</id>
    <dependencies>
      <dependency>
        <groupId>com.example</groupId>
        <artifactId>conditional-lib</artifactId>
        <version>1.0</version>
      </dependency>
    </dependencies>
  </profile>
</profiles>
""")
    assert refs == []
