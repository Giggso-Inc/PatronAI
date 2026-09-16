"""End-to-end: all six newly-added ecosystems through run_scan together,
in one repo. None of these have a real project on the development
machine to verify against — this is the synthetic-fixture equivalent of
the live-repo testing every other ecosystem in this tool received."""

from __future__ import annotations

import json

from ai_sdk_scanner.catalog.loader import load_catalog
from ai_sdk_scanner.models import Ecosystem
from ai_sdk_scanner.pipeline import run_scan


def _make_mixed_repo(tmp_path):
    (tmp_path / "pom.xml").write_text(
        '<?xml version="1.0"?>\n<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        "<dependencies>\n<dependency>\n<groupId>com.openai</groupId>\n"
        "<artifactId>openai-java</artifactId>\n<version>0.5.0</version>\n"
        "</dependency>\n</dependencies>\n</project>\n",
        encoding="utf-8",
    )
    (tmp_path / "go.mod").write_text(
        "module example.com/foo\n\nrequire github.com/sashabaranov/go-openai v1.20.0\n",
        encoding="utf-8",
    )
    (tmp_path / "Cargo.toml").write_text(
        '[dependencies]\nasync-openai = "0.20.0"\nserde = "1.0"\n', encoding="utf-8"
    )
    (tmp_path / "app.csproj").write_text(
        '<Project><ItemGroup><PackageReference Include="OpenAI" Version="2.0.0" />'
        "</ItemGroup></Project>\n",
        encoding="utf-8",
    )
    (tmp_path / "Gemfile").write_text(
        "gem 'ruby-openai', '6.0'\ngem 'rails', '7.0'\n", encoding="utf-8"
    )
    composer_data = {
        "require": {
            "php": ">=8.1",
            "openai-php/client": "^0.10.0",
            "monolog/monolog": "^3.0",
        }
    }
    (tmp_path / "composer.json").write_text(json.dumps(composer_data), encoding="utf-8")


def test_all_six_new_ecosystems_are_scanned_together(tmp_path):
    _make_mixed_repo(tmp_path)
    report = run_scan(tmp_path, load_catalog())

    ecosystems_seen = {r.ecosystem for r in report.records}
    assert ecosystems_seen == {
        Ecosystem.MAVEN, Ecosystem.GO, Ecosystem.CARGO,
        Ecosystem.NUGET, Ecosystem.RUBYGEMS, Ecosystem.COMPOSER,
    }
    assert report.coverage.manifests_found == 6
    assert report.coverage.manifests_parsed == 6
    assert report.errors == ()


def test_ai_libraries_flagged_across_all_new_ecosystems(tmp_path):
    _make_mixed_repo(tmp_path)
    report = run_scan(tmp_path, load_catalog())
    by_name = {r.dependency_name: r for r in report.records}

    ai_libs = {
        "com.openai:openai-java", "github.com/sashabaranov/go-openai",
        "async-openai", "OpenAI", "ruby-openai", "openai-php/client",
    }
    for name in ai_libs:
        assert by_name[name].is_ai_related is True, name

    non_ai = {"serde", "rails", "monolog/monolog"}
    for name in non_ai:
        assert by_name[name].is_ai_related is False, name
        assert by_name[name].category.value == "unclassified"


def test_php_platform_package_php_itself_is_not_a_dependency(tmp_path):
    _make_mixed_repo(tmp_path)
    report = run_scan(tmp_path, load_catalog())
    names = {r.dependency_name for r in report.records if r.ecosystem == Ecosystem.COMPOSER}
    assert "php" not in names


def test_ai_only_filters_across_new_ecosystems_too(tmp_path):
    _make_mixed_repo(tmp_path)
    report = run_scan(tmp_path, load_catalog(), ai_only=True)
    assert all(r.is_ai_related for r in report.records)
    assert len(report.records) == 6  # exactly one AI lib per ecosystem in this fixture
