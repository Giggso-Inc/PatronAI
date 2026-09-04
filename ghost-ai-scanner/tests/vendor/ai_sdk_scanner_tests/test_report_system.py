"""System-scan renderers."""

from __future__ import annotations

import csv
import io
import json

from ai_sdk_scanner.models import (
    Category,
    CoverageInfo,
    DependencyGroup,
    Ecosystem,
    ScanRecord,
    ScanReport,
    SystemScanReport,
    SystemScanSummary,
    VersionSource,
    VersionSpecKind,
)
from ai_sdk_scanner.report.system import render_table, to_csv, to_json, to_jsonl


def _record(name: str = "openai", repo_id: str = "local:alpha") -> ScanRecord:
    return ScanRecord(
        repo_id=repo_id,
        file_path="requirements.txt",
        dependency_name=name,
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
        raw_declaration=f"{name}>=1.0",
        match_rule=f"exact:{name}",
    )


def _project(
    *, root: str, repo_id: str, commit: str | None, warnings: tuple[str, ...] = ()
) -> ScanReport:
    return ScanReport(
        repo_id=repo_id,
        commit_sha=commit,
        is_dirty=False,
        scan_timestamp="2026-08-31T00:00:00+00:00",
        tool_version="0.1.0",
        duration_ms=1,
        records=(_record(repo_id=repo_id),),
        errors=(),
        coverage=CoverageInfo(
            manifests_found=1, manifests_parsed=1, manifests_unparsed=(),
            ecosystems_seen=("pypi",), catalog_version=1,
        ),
        warnings=warnings,
        project_root=root,
    )


def _report(projects: tuple[ScanReport, ...]) -> SystemScanReport:
    all_records = [r for p in projects for r in p.records]
    return SystemScanReport(
        host="test-host",
        scan_timestamp="2026-08-31T00:00:00+00:00",
        tool_version="0.1.0",
        duration_ms=5000,
        roots_scanned=("C:\\", "D:\\"),
        dirs_pruned=12,
        dirs_visited=340,
        access_denied_count=3,
        projects=projects,
        summary=SystemScanSummary(
            projects_found=len(projects) + 2,
            projects_with_ai_refs=len(projects),
            total_references=len(all_records),
            unique_dependencies=len({r.dependency_name for r in all_records}),
            git_projects=sum(1 for p in projects if p.commit_sha),
            manifest_only_projects=sum(1 for p in projects if not p.commit_sha),
        ),
    )


def test_jsonl_flattens_across_projects():
    report = _report((
        _project(root="D:\\alpha", repo_id="local:alpha", commit="abc123"),
        _project(root="D:\\beta", repo_id="local:beta", commit=None),
    ))
    lines = to_jsonl(report).strip().splitlines()
    assert len(lines) == 2
    repo_ids = {json.loads(line)["repo_id"] for line in lines}
    assert repo_ids == {"local:alpha", "local:beta"}


def test_json_groups_by_project_and_keeps_scan_metadata():
    report = _report((_project(root="D:\\alpha", repo_id="local:alpha", commit="abc123"),))
    data = json.loads(to_json(report))
    assert data["scan"]["roots_scanned"] == ["C:\\", "D:\\"]
    assert data["scan"]["dirs_visited"] == 340
    assert data["scan"]["access_denied_count"] == 3
    assert len(data["projects"]) == 1
    project = data["projects"][0]
    assert project["project_root"] == "D:\\alpha"
    assert project["reference_count"] == 1
    assert "warnings" in project


def test_csv_flattens_across_projects():
    report = _report((
        _project(root="D:\\alpha", repo_id="local:alpha", commit="abc123"),
        _project(root="D:\\beta", repo_id="local:beta", commit=None),
    ))
    rows = list(csv.DictReader(io.StringIO(to_csv(report))))
    assert len(rows) == 2
    assert {r["repo_id"] for r in rows} == {"local:alpha", "local:beta"}


def test_table_states_neutral_framing_and_roots():
    report = _report((_project(root="D:\\alpha", repo_id="local:alpha", commit="abc123"),))
    out = render_table(report)
    assert "evidence" in out.lower()
    assert "judgment" in out.lower()
    assert "C:\\" in out and "D:\\" in out


def test_table_distinguishes_no_git_from_no_commits():
    report = _report((
        _project(root="D:\\plain", repo_id="local:plain", commit=None,
                 warnings=("no_git_context",)),
        _project(root="D:\\fresh", repo_id="local:fresh", commit=None,
                 warnings=("no_commits_yet",)),
    ))
    out = render_table(report)
    assert "[not a git repo]" in out
    assert "[git, no commits yet]" in out


def test_table_surfaces_walk_truncation_per_project():
    report = _report((
        _project(root="D:\\huge", repo_id="local:huge", commit="abc123",
                 warnings=("walk_truncated",)),
    ))
    out = render_table(report)
    assert "file budget reached" in out


def test_table_reports_permission_denials():
    report = _report((_project(root="D:\\alpha", repo_id="local:alpha", commit="abc123"),))
    out = render_table(report)
    assert "could not be read" in out


def test_table_empty_says_so_explicitly():
    report = _report(())
    out = render_table(report)
    assert "No projects with declared dependencies found." in out
