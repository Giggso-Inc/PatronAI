"""jsonl / json / csv exporters. PLAN.md section 9.

Every exporter here writes exactly the Finding dataclass fields -- there is
no field to accidentally serialize a secret into (PLAN.md section 1.1.1).
The canary test (tests/test_canary.py) reads these files back as raw bytes
to prove that holds in practice, not just by inspection.
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict
from typing import Any

from apikey_scanner.models import Finding

FOOTER_NOTE = (
    "working-tree scan only -- secrets removed from HEAD but present in git "
    "history are NOT covered by this report (see README.md)"
)


def _finding_to_dict(f: Finding) -> dict[str, Any]:
    d = asdict(f)
    d["confidence"] = f.confidence.value
    d["detector"] = f.detector.value
    d["provenance_state"] = f.provenance_state.value
    return d


def to_jsonl(findings: list[Finding]) -> str:
    return "\n".join(json.dumps(_finding_to_dict(f), sort_keys=True) for f in findings)


def to_json(findings: list[Finding]) -> str:
    return json.dumps([_finding_to_dict(f) for f in findings], indent=2, sort_keys=True)


def to_csv(findings: list[Finding]) -> str:
    if not findings:
        return ""
    buf = io.StringIO()
    fieldnames = list(_finding_to_dict(findings[0]).keys())
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for f in findings:
        writer.writerow(_finding_to_dict(f))
    return buf.getvalue()
