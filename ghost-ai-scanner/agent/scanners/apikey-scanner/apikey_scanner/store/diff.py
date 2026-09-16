"""Scan-over-scan diff. PLAN.md section 8 diff semantics.

Uses `finding_observation` (one row per finding actually seen in a given
scan) rather than the mutable `status` column, so a diff between two
arbitrary past scans is unaffected by whatever the most recent scan did.
"""

from __future__ import annotations

from dataclasses import dataclass

from apikey_scanner.store.sqlite_store import SqliteStore


@dataclass(frozen=True, slots=True)
class ScanDiff:
    new: tuple[str, ...]
    resolved: tuple[str, ...]
    persisting: tuple[str, ...]


def _observed_finding_ids(store: SqliteStore, scan_id: int) -> set[str]:
    rows = store.connection.execute(
        "SELECT finding_id FROM finding_observation WHERE scan_id=?", (scan_id,)
    )
    return {row["finding_id"] for row in rows}


def diff_scans(store: SqliteStore, from_scan_id: int, to_scan_id: int) -> ScanDiff:
    before = _observed_finding_ids(store, from_scan_id)
    after = _observed_finding_ids(store, to_scan_id)
    return ScanDiff(
        new=tuple(sorted(after - before)),
        resolved=tuple(sorted(before - after)),
        persisting=tuple(sorted(before & after)),
    )
