"""Renderer output. PLAN.md section 8.1/8.3."""

from __future__ import annotations

import csv
import io
import json

from ai_sdk_scanner.models import (
    Category,
    CoverageInfo,
    DependencyGroup,
    Ecosystem,
    ManifestError,
    ScanRecord,
    ScanReport,
    UnparsedManifest,
    VersionSource,
    VersionSpecKind,
)
from ai_sdk_scanner.report.structured import to_csv, to_json, to_jsonl
from ai_sdk_scanner.report.table import render_table


def _sample_report() -> ScanReport:
    record = ScanRecord(
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
    return ScanReport(
        repo_id="local:test",
        commit_sha="abc123",
        is_dirty=False,
        scan_timestamp="2026-08-31T00:00:00+00:00",
        tool_version="0.1.0",
        duration_ms=42,
        records=(record,),
        errors=(ManifestError(path="bad.json", kind="manifest_parse_failed", detail="boom"),),
        coverage=CoverageInfo(
            manifests_found=2, manifests_parsed=1,
            manifests_unparsed=(
                UnparsedManifest(path="setup.py", reason="python_setup_py_unparsed"),
            ),
            ecosystems_seen=("pypi",), catalog_version=1,
        ),
    )


def test_jsonl_one_record_per_line():
    lines = to_jsonl(_sample_report()).strip().splitlines()
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["dependency_name"] == "openai"
    assert parsed["version_spec_kind"] == "range"


def test_json_envelope_has_every_key_and_no_omission():
    data = json.loads(to_json(_sample_report()))
    assert data["scan"]["repo_id"] == "local:test"
    record = data["records"][0]
    for key in ("file_last_commit_sha", "commit_sha"):
        assert key in record
    assert len(data["errors"]) == 1
    assert data["coverage"]["manifests_found"] == 2
    assert len(data["coverage"]["manifests_unparsed"]) == 1


def test_csv_round_trips_the_dependency_name():
    reader = csv.DictReader(io.StringIO(to_csv(_sample_report())))
    rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["dependency_name"] == "openai"
    assert rows[0]["ecosystem"] == "pypi"


def test_table_states_the_neutral_framing():
    output = render_table(_sample_report())
    assert "evidence" in output.lower()
    assert "judgment" in output.lower()


def test_table_shows_dependency_and_never_truncates_silently():
    output = render_table(_sample_report())
    assert "openai" in output
    assert "requirements.txt" in output


def test_table_shows_unparsed_manifests():
    output = render_table(_sample_report())
    assert "setup.py" in output


def test_table_empty_records_says_so_explicitly():
    empty = ScanReport(
        repo_id="local:test", commit_sha=None, is_dirty=False,
        scan_timestamp="2026-08-31T00:00:00+00:00", tool_version="0.1.0", duration_ms=1,
        records=(), errors=(),
        coverage=CoverageInfo(
            manifests_found=0, manifests_parsed=0, manifests_unparsed=(),
            ecosystems_seen=(), catalog_version=1,
        ),
    )
    output = render_table(empty)
    assert "No dependencies found" in output
