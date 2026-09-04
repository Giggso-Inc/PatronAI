"""SQLite findings store. PLAN.md section 8.

The database is sensitive by location, not by content: it names exactly
which file and line in which repo holds a live key, even though it stores
no secret bytes. Created 0600 and the caller is responsible for ensuring
its parent directory is gitignored (cli.py does this on first run).
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
from collections.abc import Iterable
from importlib import resources
from pathlib import Path

from apikey_scanner.errors import StoreError
from apikey_scanner.models import Finding


class SqliteStore:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._conn = sqlite3.connect(str(self.db_path))
        except sqlite3.Error as exc:
            raise StoreError(f"could not open findings database at {self.db_path}") from exc
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._apply_schema()
        self._secure_permissions()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> SqliteStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _apply_schema(self) -> None:
        schema_sql = (
            resources.files("apikey_scanner.store").joinpath("schema.sql").read_text(
                encoding="utf-8"
            )
        )
        self._conn.executescript(schema_sql)
        self._conn.commit()

    def _secure_permissions(self) -> None:
        # Best-effort: some platforms/filesystems (e.g. certain Windows
        # setups) don't support POSIX permission bits at all.
        with contextlib.suppress(OSError):
            os.chmod(self.db_path, 0o600)

    def start_scan(
        self,
        *,
        scan_timestamp: str,
        tool_version: str,
        catalog_version: str,
        roots_json: str,
        host: str | None,
    ) -> int:
        cur = self._conn.execute(
            "INSERT INTO scan (scan_timestamp, tool_version, catalog_version, roots_json, host) "
            "VALUES (?, ?, ?, ?, ?)",
            (scan_timestamp, tool_version, catalog_version, roots_json, host),
        )
        self._conn.commit()
        scan_id = cur.lastrowid
        if scan_id is None:
            raise StoreError("failed to allocate scan_id")
        return scan_id

    def finish_scan(
        self,
        scan_id: int,
        *,
        repos_scanned: int,
        files_scanned: int,
        files_skipped: int,
        findings_total: int,
        duration_ms: int,
    ) -> None:
        self._conn.execute(
            "UPDATE scan SET repos_scanned=?, files_scanned=?, files_skipped=?, "
            "findings_total=?, duration_ms=? WHERE scan_id=?",
            (repos_scanned, files_scanned, files_skipped, findings_total, duration_ms, scan_id),
        )
        self._conn.commit()

    def record_findings(
        self, scan_id: int, findings: Iterable[Finding], scanned_repo_ids: set[str]
    ) -> None:
        findings = list(findings)
        for f in findings:
            existing = self._conn.execute(
                "SELECT finding_id FROM finding WHERE finding_id=?", (f.finding_id,)
            ).fetchone()
            if existing is None:
                self._conn.execute(
                    """
                    INSERT INTO finding (
                        finding_id, repo_id, repo_path, file_path, line_number,
                        column_start, match_length, matched_pattern_type, pattern_id,
                        provider, confidence, detector, entropy_bits, commit_sha,
                        author_name, author_email, author_timestamp, provenance_state,
                        is_git_tracked, is_gitignored, in_test_path,
                        first_seen_scan_id, last_seen_scan_id, status, resolved_scan_id,
                        secret_fingerprint
                    ) VALUES (?,?,?,?,?, ?,?,?,?, ?,?,?,?,?, ?,?,?,?, ?,?,?, ?,?,?,?, ?)
                    """,
                    (
                        f.finding_id, f.repo_id, f.repo_path, f.file_path, f.line_number,
                        f.column_start, f.match_length, f.matched_pattern_type, f.pattern_id,
                        f.provider, f.confidence.value, f.detector.value, f.entropy_bits,
                        f.commit_sha, f.author_name, f.author_email, f.author_timestamp,
                        f.provenance_state.value, int(f.is_git_tracked), int(f.is_gitignored),
                        int(f.in_test_path), scan_id, scan_id, "open", None,
                        f.secret_fingerprint,
                    ),
                )
            else:
                self._conn.execute(
                    """
                    UPDATE finding SET
                        line_number=?, column_start=?, match_length=?, commit_sha=?,
                        author_name=?, author_email=?, author_timestamp=?,
                        provenance_state=?, is_git_tracked=?, is_gitignored=?,
                        in_test_path=?, last_seen_scan_id=?, status='open',
                        resolved_scan_id=NULL, secret_fingerprint=?
                    WHERE finding_id=?
                    """,
                    (
                        f.line_number, f.column_start, f.match_length, f.commit_sha,
                        f.author_name, f.author_email, f.author_timestamp,
                        f.provenance_state.value, int(f.is_git_tracked), int(f.is_gitignored),
                        int(f.in_test_path), scan_id, f.secret_fingerprint, f.finding_id,
                    ),
                )
            self._conn.execute(
                "INSERT OR REPLACE INTO finding_observation (finding_id, scan_id, line_number) "
                "VALUES (?, ?, ?)",
                (f.finding_id, scan_id, f.line_number),
            )

        if scanned_repo_ids:
            placeholders = ",".join("?" for _ in scanned_repo_ids)
            self._conn.execute(
                f"UPDATE finding SET status='resolved', resolved_scan_id=? "
                f"WHERE status='open' AND last_seen_scan_id < ? AND repo_id IN ({placeholders})",
                (scan_id, scan_id, *scanned_repo_ids),
            )
        self._conn.commit()

    def query_findings(
        self,
        *,
        status: str | None = None,
        repo_id: str | None = None,
        confidences: tuple[str, ...] | None = None,
        since_scan_id: int | None = None,
    ) -> list[sqlite3.Row]:
        clauses: list[str] = []
        params: list[object] = []
        if status is not None:
            clauses.append("finding.status=?")
            params.append(status)
        if repo_id is not None:
            clauses.append("finding.repo_id=?")
            params.append(repo_id)
        if confidences:
            clauses.append(f"finding.confidence IN ({','.join('?' for _ in confidences)})")
            params.extend(confidences)
        if since_scan_id is not None:
            clauses.append("finding.first_seen_scan_id >= ?")
            params.append(since_scan_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        query = (
            "SELECT finding.*, scan.scan_timestamp AS scan_timestamp "
            "FROM finding JOIN scan ON scan.scan_id = finding.last_seen_scan_id "
            f"{where} ORDER BY finding.repo_id, finding.file_path, finding.line_number"
        )
        return list(self._conn.execute(query, params))

    def add_allowlist(
        self, finding_id: str, reason: str, added_by: str | None, added_at: str
    ) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO allowlist (finding_id, reason, added_by, added_at) "
            "VALUES (?, ?, ?, ?)",
            (finding_id, reason, added_by, added_at),
        )
        self._conn.execute(
            "UPDATE finding SET status='allowlisted' WHERE finding_id=?", (finding_id,)
        )
        self._conn.commit()

    def remove_allowlist(self, finding_id: str) -> None:
        self._conn.execute("DELETE FROM allowlist WHERE finding_id=?", (finding_id,))
        self._conn.execute(
            "UPDATE finding SET status='open' WHERE finding_id=? AND status='allowlisted'",
            (finding_id,),
        )
        self._conn.commit()

    def list_allowlist(self) -> list[sqlite3.Row]:
        return list(self._conn.execute("SELECT * FROM allowlist ORDER BY added_at"))

    def list_scans(self) -> list[sqlite3.Row]:
        return list(self._conn.execute("SELECT * FROM scan ORDER BY scan_id"))

    @property
    def connection(self) -> sqlite3.Connection:
        return self._conn
