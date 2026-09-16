"""Renderers for a whole-system scan (many projects, one report).

The JSONL shape is deliberately unchanged from single-repo mode: one flat
record per line, each already carrying `repo_id` and `file_path`, so the
same downstream consumer works for both modes. Only the human table and
the JSON envelope gain per-project grouping.
"""

from __future__ import annotations

import csv
import io
import json
import shutil
from dataclasses import asdict
from typing import Any

from ai_sdk_scanner.models import SystemScanReport
from ai_sdk_scanner.report.structured import _CSV_FIELDS, _record_dict, csv_row

_MIN_WIDTH = 80


def to_jsonl(report: SystemScanReport) -> str:
    lines = [
        json.dumps(_record_dict(r), ensure_ascii=False)
        for project in report.projects
        for r in project.records
    ]
    return "\n".join(lines) + ("\n" if lines else "")


def to_json(report: SystemScanReport, *, indent: int = 2) -> str:
    payload: dict[str, Any] = {
        "scan": {
            "host": report.host,
            "scan_timestamp": report.scan_timestamp,
            "tool_version": report.tool_version,
            "duration_ms": report.duration_ms,
            "roots_scanned": list(report.roots_scanned),
            "dirs_visited": report.dirs_visited,
            "dirs_pruned": report.dirs_pruned,
            "access_denied_count": report.access_denied_count,
        },
        "summary": asdict(report.summary),
        "projects": [
            {
                "project_root": p.project_root,
                "repo_id": p.repo_id,
                "commit_sha": p.commit_sha,
                "is_dirty": p.is_dirty,
                "reference_count": len(p.records),
                "warnings": list(p.warnings),
                "coverage": {
                    "manifests_found": p.coverage.manifests_found,
                    "manifests_parsed": p.coverage.manifests_parsed,
                    "manifests_unparsed": [asdict(u) for u in p.coverage.manifests_unparsed],
                    "ecosystems_seen": list(p.coverage.ecosystems_seen),
                },
                "records": [_record_dict(r) for r in p.records],
                "errors": [asdict(e) for e in p.errors],
            }
            for p in report.projects
        ],
        "warnings": list(report.warnings),
    }
    return json.dumps(payload, indent=indent, ensure_ascii=False)


def to_csv(report: SystemScanReport) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for project in report.projects:
        for record in project.records:
            writer.writerow(csv_row(record))
    return buf.getvalue()


def render_table(report: SystemScanReport) -> str:
    width = max(shutil.get_terminal_size(fallback=(_MIN_WIDTH, 24)).columns, _MIN_WIDTH)
    name_width = max(22, min(34, width - 52))

    lines: list[str] = []
    lines.append(f"Dependency Inventory — system scan of {report.host}")
    lines.append(f"roots: {', '.join(report.roots_scanned)}")
    lines.append(
        f"scanned {report.scan_timestamp} in {report.duration_ms / 1000:.1f}s "
        f"({report.dirs_visited} dirs visited, {report.dirs_pruned} pruned)"
    )
    lines.append("")
    lines.append(
        "Every declared dependency is listed; '*' marks one the AI/ML catalog "
        "recognised. Findings are evidence of what code declares, not a judgment."
    )
    lines.append("")

    if not report.projects:
        lines.append("No projects with declared dependencies found.")
    for project in sorted(report.projects, key=lambda p: (p.project_root or "").lower()):
        # Distinguish "not a git repo at all" from "a git repo with no
        # commits yet" -- both have commit_sha=None, but labelling the
        # second one "[no git]" alongside "[DIRTY]" is self-contradictory.
        if "no_git_context" in project.warnings:
            marker = "  [not a git repo]"
        elif "no_commits_yet" in project.warnings:
            marker = "  [git, no commits yet]"
        else:
            marker = ""
        dirty = "  [DIRTY]" if project.is_dirty else ""
        lines.append(f"== {project.project_root}{marker}{dirty}")
        lines.append(f"   repo_id: {project.repo_id}")
        if project.commit_sha:
            lines.append(f"   commit:  {project.commit_sha[:12]}")
        if "walk_truncated" in project.warnings:
            lines.append(
                "   NOTE:    file budget reached while searching this project — "
                "some manifests may be missing (raise --max-files-per-project)"
            )
        ai_count = sum(1 for r in project.records if r.is_ai_related)
        lines.append(
            f"   deps:    {len(project.records)} total, {ai_count} AI-classified"
        )
        header = (
            f"     {'':1} {'Dependency':<{name_width}} {'Version':<14} "
            f"{'Category':<20} File"
        )
        lines.append(header)
        # AI-classified rows first, so they stay visible in a project with
        # hundreds of dependencies even when the terminal scrolls.
        ordered = sorted(
            project.records,
            key=lambda x: (
                not x.is_ai_related,
                x.category.value,
                x.dependency_name.lower(),
            ),
        )
        for r in ordered:
            if len(r.dependency_name) <= name_width:
                name = r.dependency_name
            else:
                name = r.dependency_name[: name_width - 1] + "…"
            version = r.dependency_version or "(unpinned)"
            if len(version) > 14:
                version = version[:13] + "…"
            glyph = "*" if r.is_ai_related else " "
            lines.append(
                f"     {glyph} {name:<{name_width}} {version:<14} "
                f"{r.category.value:<20} {r.file_path}"
            )
        lines.append("")

    s = report.summary
    lines.append(
        f"Summary: {s.projects_found} project(s) discovered, "
        f"{s.projects_with_any_refs} with declared dependencies"
    )
    lines.append(
        f"         {s.total_references} dependency reference(s), "
        f"{s.unique_dependencies} unique package(s)"
    )
    lines.append(
        f"         of which AI-classified: {s.ai_references} reference(s), "
        f"{s.unique_ai_dependencies} unique package(s), "
        f"across {s.projects_with_ai_refs} project(s)"
    )
    lines.append(
        f"         {s.git_projects} git project(s), {s.manifest_only_projects} without git"
    )
    if report.access_denied_count:
        lines.append(
            f"         {report.access_denied_count} directory/ies could not be read "
            "(permissions) — results may be incomplete"
        )
    if report.warnings:
        lines.append(f"         warnings: {', '.join(report.warnings)}")

    return "\n".join(lines) + "\n"
