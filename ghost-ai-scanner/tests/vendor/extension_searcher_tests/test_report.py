"""PLAN.md section 10.1: table and JSON are equal, first-class deliverables
from the same ScanReport — these tests build a minimal report by hand and
check both renderers against it."""

from __future__ import annotations

import csv
import io
import json

from extension_searcher.models import (
    BrowserHit,
    Confidence,
    Engine,
    ExtensionRecord,
    InstallOrigin,
    ProfileHit,
    ScanError,
    ScanReport,
    ScanSummary,
)
from extension_searcher.report.structured import to_csv, to_json, to_jsonl
from extension_searcher.report.table import render_table


def _sample_report() -> ScanReport:
    profile = ProfileHit("Default", "Default", "/fake/Default", Engine.CHROMIUM)
    record = ExtensionRecord(
        extension_id="abcdefghijklmnopabcdefghijklmnop",
        name="Sample Extension",
        version="1.0",
        description=None,
        browser="Google Chrome",
        browser_channel="Stable",
        engine=Engine.CHROMIUM,
        profile_dir="Default",
        profile_name="Default",
        install_path="/fake/path",
        enabled=True,
        disabled_reason=None,
        state_source="secure_preferences",
        install_origin=InstallOrigin.WEBSTORE,
        update_url=None,
        signed_state=None,
        is_builtin=False,
        is_unpacked=False,
        manifest_version=3,
        confidence=Confidence.FULL,
    )
    browser = BrowserHit(
        "Google Chrome", Engine.CHROMIUM, True, ("/fake/User Data",), (profile,), False
    )
    summary = ScanSummary(
        browsers_found=1, profiles=1, extensions=1, unique_extensions=1,
        disabled=0, sideloaded=0,
    )
    return ScanReport(
        host="test-host",
        os_name="windows",
        started_at="2026-08-27T00:00:00+00:00",
        finished_at="2026-08-27T00:00:01+00:00",
        tool_version="0.1.0",
        duration_ms=1000,
        browsers=(browser,),
        extensions=(record,),
        errors=(ScanError("/fake/bad.json", "json_decode", "boom"),),
        summary=summary,
        unverified_paths=(),
    )


def test_table_contains_browser_and_extension_name():
    report = _sample_report()
    output = render_table(report, no_color=True)
    assert "Google Chrome" in output
    assert "Sample Extension" in output
    assert "abcdefghijklmnopabcdefghijklmnop" in output  # ID must never be truncated
    assert "1 error(s)" in output


def test_json_contains_every_schema_key_even_if_null():
    report = _sample_report()
    data = json.loads(to_json(report))
    ext = data["extensions"][0]
    # PLAN.md section 10.1: every field present even when null.
    for key in ("description", "update_url", "signed_state", "install_time"):
        assert key in ext
        assert ext[key] is None
    assert data["scan"]["host"] == "test-host"
    assert data["summary"]["extensions"] == 1
    assert len(data["errors"]) == 1


def test_jsonl_one_record_per_line():
    report = _sample_report()
    lines = to_jsonl(report).strip().splitlines()
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["name"] == "Sample Extension"


def test_csv_flattens_tuple_fields_with_semicolons():
    report = _sample_report()
    reader = csv.DictReader(io.StringIO(to_csv(report)))
    rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["name"] == "Sample Extension"
    assert rows[0]["engine"] == "chromium"
