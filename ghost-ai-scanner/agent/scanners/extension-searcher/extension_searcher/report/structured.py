"""JSON / JSONL / CSV renderers. PLAN.md section 10.1.

Every schema key is present even when null — no key omission, so
downstream consumers never need `.get()` guards.
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict
from typing import Any

from extension_searcher.models import ExtensionRecord, ScanReport

_CSV_FIELDS = (
    "extension_id", "name", "version", "description",
    "browser", "browser_channel", "engine", "profile_dir", "profile_name",
    "install_path", "enabled", "disabled_reason", "state_source",
    "install_origin", "update_url", "signed_state", "is_builtin", "is_unpacked",
    "manifest_version", "permissions", "host_permissions",
    "content_script_matches", "has_background_worker",
    "install_time", "update_time", "source_files", "confidence", "warnings",
)


def _record_dict(record: ExtensionRecord) -> dict[str, Any]:
    d = asdict(record)
    d["engine"] = record.engine.value
    d["install_origin"] = record.install_origin.value
    d["confidence"] = record.confidence.value
    return d


def report_to_dict(report: ScanReport) -> dict[str, Any]:
    return {
        "scan": {
            "host": report.host,
            "os": report.os_name,
            "started_at": report.started_at,
            "finished_at": report.finished_at,
            "tool_version": report.tool_version,
            "duration_ms": report.duration_ms,
        },
        "browsers": [
            {
                "name": b.name,
                "engine": b.engine.value,
                "found": b.found,
                "roots_checked": list(b.roots_checked),
                "profiles": len(b.profiles),
                "unverified": b.unverified,
            }
            for b in report.browsers
        ],
        "extensions": [_record_dict(r) for r in report.extensions],
        "errors": [asdict(e) for e in report.errors],
        "summary": asdict(report.summary),
        "unverified_paths": list(report.unverified_paths),
    }


def to_json(report: ScanReport, *, indent: int = 2) -> str:
    return json.dumps(report_to_dict(report), indent=indent, ensure_ascii=False)


def to_jsonl(report: ScanReport) -> str:
    lines = [json.dumps(_record_dict(r), ensure_ascii=False) for r in report.extensions]
    return "\n".join(lines) + ("\n" if lines else "")


def to_csv(report: ScanReport) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for record in report.extensions:
        row = _record_dict(record)
        tuple_fields = (
            "permissions", "host_permissions", "content_script_matches",
            "source_files", "warnings",
        )
        for key in tuple_fields:
            row[key] = ";".join(row[key])
        writer.writerow(row)
    return buf.getvalue()
