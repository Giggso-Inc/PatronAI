"""build.gradle / build.gradle.kts. No real Gradle project exists on this
machine — verified only against synthetic fixtures."""

from __future__ import annotations

from ai_sdk_scanner.models import DependencyGroup
from ai_sdk_scanner.parsers.java_gradle import parse


def _write_and_parse(tmp_path, content, filename="build.gradle"):
    path = tmp_path / filename
    path.write_text(content, encoding="utf-8")
    return parse(path, file_path=filename)


def test_groovy_single_quote_form(tmp_path):
    refs = _write_and_parse(tmp_path, "implementation 'com.openai:openai-java:0.5.0'\n")
    assert len(refs) == 1
    assert refs[0].name == "com.openai:openai-java"
    assert refs[0].version_spec == "0.5.0"
    assert refs[0].dependency_group == DependencyGroup.MAIN


def test_kotlin_dsl_paren_form(tmp_path):
    refs = _write_and_parse(
        tmp_path, 'implementation("com.openai:openai-java:0.5.0")\n', filename="build.gradle.kts"
    )
    assert refs[0].name == "com.openai:openai-java"
    assert refs[0].version_spec == "0.5.0"


def test_named_argument_form(tmp_path):
    refs = _write_and_parse(
        tmp_path,
        "implementation group: 'com.openai', name: 'openai-java', version: '0.5.0'\n",
    )
    assert refs[0].name == "com.openai:openai-java"
    assert refs[0].version_spec == "0.5.0"


def test_test_implementation_is_dev_group(tmp_path):
    refs = _write_and_parse(tmp_path, "testImplementation 'org.junit:junit:4.13'\n")
    assert refs[0].dependency_group == DependencyGroup.DEV


def test_compile_only_is_optional(tmp_path):
    refs = _write_and_parse(tmp_path, "compileOnly 'org.projectlombok:lombok:1.18.30'\n")
    assert refs[0].dependency_group == DependencyGroup.OPTIONAL
    assert refs[0].is_optional is True


def test_annotation_processor_is_dev_group(tmp_path):
    refs = _write_and_parse(tmp_path, "annotationProcessor 'org.projectlombok:lombok:1.18.30'\n")
    assert refs[0].dependency_group == DependencyGroup.DEV


def test_version_catalog_reference_is_skipped_not_guessed(tmp_path):
    # A real, named limitation: libs.some.library can't be resolved to a
    # group:artifact:version triple without reading the version catalog
    # TOML separately, which this parser does not do.
    refs = _write_and_parse(tmp_path, "implementation(libs.some.library)\n")
    assert refs == []


def test_comment_line_is_ignored(tmp_path):
    refs = _write_and_parse(tmp_path, "// implementation 'a:b:1.0'\nimplementation 'c:d:2.0'\n")
    assert len(refs) == 1
    assert refs[0].name == "c:d"


def test_unrecognized_configuration_is_ignored(tmp_path):
    refs = _write_and_parse(tmp_path, "somethingRandom 'a:b:1.0'\n")
    assert refs == []


def test_line_number_is_recorded(tmp_path):
    refs = _write_and_parse(
        tmp_path, "plugins {\n    id 'java'\n}\n\nimplementation 'a:b:1.0'\n"
    )
    assert refs[0].line_number == 5
