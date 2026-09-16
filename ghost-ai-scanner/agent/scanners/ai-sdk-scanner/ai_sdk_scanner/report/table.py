"""Human-readable table renderer.

Grouped by category, since "what kinds of AI libraries does this repo
reference" is the question a human reader usually has — the JSONL/JSON/CSV
formats stay file-centric for machine consumption.
"""

from __future__ import annotations

import shutil

from ai_sdk_scanner.models import Category, ScanRecord, ScanReport

_MIN_WIDTH = 80


def render_table(report: ScanReport) -> str:
    width = max(shutil.get_terminal_size(fallback=(_MIN_WIDTH, 24)).columns, _MIN_WIDTH)
    name_width = max(24, width - 56)

    lines: list[str] = []
    lines.append(f"Dependency Inventory — {report.repo_id}")
    commit_display = report.commit_sha[:12] if report.commit_sha else "(no commits)"
    dirty_note = " [DIRTY — uncommitted changes present]" if report.is_dirty else ""
    lines.append(f"commit {commit_display}{dirty_note}")
    lines.append(f"scanned {report.scan_timestamp}")
    lines.append("")
    lines.append(
        "Every declared dependency is listed, grouped by category. Findings are "
        "evidence of what code declares, not a judgment."
    )
    lines.append("")

    by_category: dict[str, list[ScanRecord]] = {}
    for r in report.records:
        by_category.setdefault(r.category.value, []).append(r)

    if not by_category:
        lines.append("No dependencies found in any parsed manifest.")

    # AI categories first, `unclassified` last: it is usually the largest
    # group and burying the classified ones under it defeats the point.
    def category_order(name: str) -> tuple[int, str]:
        return (1 if name == Category.UNCLASSIFIED.value else 0, name)

    for category in sorted(by_category, key=category_order):
        records = by_category[category]
        lines.append(f"== {category} — {len(records)} reference(s) ==")
        header = f"  {'Dependency':<{name_width}} {'Version':<16} {'Ecosystem':<8} File"
        lines.append(header)
        for r in sorted(records, key=lambda x: (x.dependency_name.lower(), x.file_path)):
            if len(r.dependency_name) <= name_width:
                name = r.dependency_name
            else:
                name = r.dependency_name[: name_width - 1] + "…"
            marker = "" if r.content_matches_commit else " *"
            lines.append(
                f"  {name:<{name_width}} {r.dependency_version:<16} "
                f"{r.ecosystem.value:<8} {r.file_path}{marker}"
            )
        lines.append("")

    cov = report.coverage
    lines.append(
        f"Coverage: {cov.manifests_parsed}/{cov.manifests_found} manifest(s) parsed, "
        f"{len(cov.manifests_unparsed)} unparsed, {len(report.records)} reference(s) found"
    )
    if cov.manifests_unparsed:
        for u in cov.manifests_unparsed:
            lines.append(f"  - not parsed: {u.path} ({u.reason})")
    if report.is_dirty:
        lines.append(
            "* marks a reference whose file has uncommitted changes — "
            "content may not match commit_sha"
        )
    if report.errors:
        lines.append(f"{len(report.errors)} manifest(s) failed to parse — see --format=json")
    if report.warnings:
        lines.append(f"warnings: {', '.join(report.warnings)}")

    return "\n".join(lines) + "\n"
