"""CLI argument handling and exit codes. PLAN.md section 8.4.

`run_scan` is monkeypatched throughout so these test CLI logic (exit-code
contract, rendering dispatch, bad-path handling) without touching a real
repository — a real end-to-end run is covered separately in test_pipeline.py.
"""

from __future__ import annotations

import json

import pytest

from ai_sdk_scanner import cli
from ai_sdk_scanner.models import (
    Category,
    CoverageInfo,
    DependencyGroup,
    Ecosystem,
    ManifestError,
    ScanRecord,
    ScanReport,
    VersionSource,
    VersionSpecKind,
)


def _fake_record(**overrides) -> ScanRecord:
    base = dict(
        repo_id="local:test",
        file_path="requirements.txt",
        dependency_name="openai",
        dependency_version=">=1.0",
        commit_sha="abc123",
        scan_timestamp="2026-08-31T00:00:00+00:00",
        version_spec_kind=VersionSpecKind.RANGE,
        version_source=VersionSource.DECLARED,
        content_matches_commit=True,
        ecosystem=Ecosystem.PYPI,
        category=Category.LLM_SDK,
        dependency_group=DependencyGroup.MAIN,
        is_direct=True,
        raw_declaration="openai>=1.0",
        match_rule="exact:openai",
    )
    base.update(overrides)
    return ScanRecord(**base)


def _fake_report(*, records=(), errors=(), unparsed=()) -> ScanReport:
    return ScanReport(
        repo_id="local:test",
        commit_sha="abc123",
        is_dirty=False,
        scan_timestamp="2026-08-31T00:00:00+00:00",
        tool_version="0.1.0",
        duration_ms=0,
        records=tuple(records),
        errors=tuple(errors),
        coverage=CoverageInfo(
            manifests_found=1, manifests_parsed=1, manifests_unparsed=tuple(unparsed),
            ecosystems_seen=("pypi",), catalog_version=1,
        ),
    )


def test_target_path_not_found_returns_exit_2(tmp_path):
    missing = tmp_path / "does_not_exist"
    exit_code = cli.main([str(missing)])
    assert exit_code == 2


def test_target_path_is_a_file_not_a_dir_returns_exit_2(tmp_path):
    f = tmp_path / "a_file.txt"
    f.write_text("x")
    exit_code = cli.main([str(f)])
    assert exit_code == 2


def test_exit_0_on_clean_scan(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "run_scan", lambda *a, **k: _fake_report(records=(_fake_record(),)))
    exit_code = cli.main([str(tmp_path), "--format", "json"])
    assert exit_code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["records"][0]["dependency_name"] == "openai"


def test_exit_1_when_manifest_errors_present(tmp_path, monkeypatch):
    err = ManifestError(path="bad.json", kind="manifest_parse_failed", detail="boom")
    monkeypatch.setattr(cli, "run_scan", lambda *a, **k: _fake_report(errors=(err,)))
    exit_code = cli.main([str(tmp_path), "--format", "json"])
    assert exit_code == 1


def test_default_format_is_jsonl(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "run_scan", lambda *a, **k: _fake_report(records=(_fake_record(),)))
    cli.main([str(tmp_path)])
    out = capsys.readouterr().out
    parsed = json.loads(out.strip().splitlines()[0])
    assert parsed["dependency_name"] == "openai"


@pytest.mark.parametrize("fmt", ["jsonl", "json", "csv", "table"])
def test_every_format_renders_without_error(tmp_path, monkeypatch, fmt):
    monkeypatch.setattr(cli, "run_scan", lambda *a, **k: _fake_report(records=(_fake_record(),)))
    exit_code = cli.main([str(tmp_path), "--format", fmt])
    assert exit_code == 0


def test_output_flag_writes_to_file(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "run_scan", lambda *a, **k: _fake_report(records=(_fake_record(),)))
    out_path = tmp_path / "out.json"
    exit_code = cli.main([str(tmp_path), "--format", "json", "--output", str(out_path)])
    assert exit_code == 0
    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert data["records"][0]["dependency_name"] == "openai"


def test_invalid_catalog_path_returns_exit_3(tmp_path):
    bad_catalog = tmp_path / "bad_catalog.json"
    bad_catalog.write_text("not valid json")
    exit_code = cli.main([str(tmp_path), "--catalog", str(bad_catalog)])
    assert exit_code == 3


def test_repo_id_override_is_passed_through(tmp_path, monkeypatch):
    captured = {}

    def fake_run_scan(repo_root, catalog, **kwargs):
        captured.update(kwargs)
        return _fake_report()

    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    cli.main([str(tmp_path), "--repo-id", "my-org/my-repo"])
    assert captured["explicit_repo_id"] == "my-org/my-repo"


def test_no_respect_gitignore_flag(tmp_path, monkeypatch):
    captured = {}

    def fake_run_scan(repo_root, catalog, **kwargs):
        captured.update(kwargs)
        return _fake_report()

    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    cli.main([str(tmp_path), "--no-respect-gitignore"])
    assert captured["respect_gitignore"] is False
