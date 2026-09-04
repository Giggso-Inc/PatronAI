"""jsonl (default/primary), json, and csv renderers. PLAN.md section 8.1.

Every schema key is present in JSON/JSONL output even when null — no key
omission, so a downstream consumer never needs a `.get()` guard.
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict
from typing import Any

from ai_sdk_scanner.models import ScanRecord, ScanReport

_TUPLE_FIELDS = ("extras", "version_constraints")

# Full flat column set. Ordered by concern, not alphabetically, so the CSV
# reads left-to-right from identity -> classification -> provenance.
_CSV_FIELDS = (
    # Identity (the six originally-specified fields)
    "repo_id", "file_path", "dependency_name", "dependency_version",
    "commit_sha", "scan_timestamp",
    # Name resolution
    "normalized_name", "extras",
    # Version detail
    "version_spec_kind", "version_source", "version_constraints",
    "environment_marker",
    # Location
    "line_number", "manifest_kind",
    # Classification
    "ecosystem", "category", "is_ai_related", "dependency_group",
    "is_direct", "is_optional",
    # Package source
    "declared_index_url", "vcs_url", "vcs_ref", "local_path",
    # Lockfile supply-chain metadata
    "resolved_url", "integrity", "declared_license", "has_install_script",
    # Manifest fingerprint
    "manifest_sha256", "manifest_mtime", "manifest_size",
    # Git provenance
    "content_matches_commit", "git_branch", "git_remote_url",
    "commit_date", "commit_author",
    "file_last_commit_sha", "file_last_commit_date", "file_last_commit_author",
    # Project context (--system mode)
    "project_root", "project_name", "project_discovered_by",
    # Auditability
    "raw_declaration", "match_rule",
)


def _record_dict(record: ScanRecord) -> dict[str, Any]:
    d = asdict(record)
    d["version_spec_kind"] = record.version_spec_kind.value
    d["version_source"] = record.version_source.value
    d["ecosystem"] = record.ecosystem.value
    d["category"] = record.category.value
    d["dependency_group"] = record.dependency_group.value
    return d


def to_jsonl(report: ScanReport) -> str:
    lines = [json.dumps(_record_dict(r), ensure_ascii=False) for r in report.records]
    return "\n".join(lines) + ("\n" if lines else "")


def report_to_dict(report: ScanReport) -> dict[str, Any]:
    return {
        "scan": {
            "repo_id": report.repo_id,
            "commit_sha": report.commit_sha,
            "is_dirty": report.is_dirty,
            "scan_timestamp": report.scan_timestamp,
            "tool_version": report.tool_version,
            "duration_ms": report.duration_ms,
        },
        "records": [_record_dict(r) for r in report.records],
        "errors": [asdict(e) for e in report.errors],
        "coverage": {
            "manifests_found": report.coverage.manifests_found,
            "manifests_parsed": report.coverage.manifests_parsed,
            "manifests_unparsed": [asdict(u) for u in report.coverage.manifests_unparsed],
            "ecosystems_seen": list(report.coverage.ecosystems_seen),
            "catalog_version": report.coverage.catalog_version,
        },
        "warnings": list(report.warnings),
    }


def to_json(report: ScanReport, *, indent: int = 2) -> str:
    return json.dumps(report_to_dict(report), indent=indent, ensure_ascii=False)


def csv_row(record: ScanRecord) -> dict[str, Any]:
    """A record flattened for CSV: tuple fields joined with ';'."""
    row = _record_dict(record)
    for key in _TUPLE_FIELDS:
        value = row.get(key)
        if isinstance(value, (list, tuple)):
            row[key] = ";".join(str(v) for v in value)
    return row


def to_csv(report: ScanReport) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for record in report.records:
        writer.writerow(csv_row(record))
    return buf.getvalue()
