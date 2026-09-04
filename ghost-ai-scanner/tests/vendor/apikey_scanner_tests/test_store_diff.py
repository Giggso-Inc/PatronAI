"""Scan-over-scan new/resolved/persisting semantics. PLAN.md section 8."""

from __future__ import annotations

from pathlib import Path

from apikey_scanner.catalog.loader import load_catalog
from apikey_scanner.config import ScannerConfig
from apikey_scanner.pipeline import run_scan
from apikey_scanner.store.diff import diff_scans
from apikey_scanner.store.sqlite_store import SqliteStore
from .conftest import commit_all, init_git_repo


def _run_and_record(repo: Path, store: SqliteStore, catalog, config, ts: str) -> int:
    findings, summary, scanned_repo_ids = run_scan([repo], catalog, config)
    scan_id = store.start_scan(
        scan_timestamp=ts,
        tool_version="test",
        catalog_version=catalog.version,
        roots_json="[]",
        host="test-host",
    )
    store.record_findings(scan_id, findings, scanned_repo_ids)
    store.finish_scan(
        scan_id,
        repos_scanned=summary.repos_scanned,
        files_scanned=summary.files_scanned,
        files_skipped=summary.files_skipped,
        findings_total=summary.findings_total,
        duration_ms=1,
    )
    return scan_id


def test_new_resolved_persisting_across_two_scans(tmp_path: Path):
    repo = tmp_path / "repo"
    init_git_repo(repo)
    (repo / "app.py").write_text('key = "AKIAQ7ZP4XKM9LWD2FTR"\n', encoding="utf-8")
    commit_all(repo, "initial key")

    catalog = load_catalog()
    config = ScannerConfig()
    db_path = tmp_path / "findings.db"

    with SqliteStore(db_path) as store:
        scan_1 = _run_and_record(repo, store, catalog, config, "2026-01-01T00:00:00+00:00")

        # Second scan: the original key persists, a second file adds a new one.
        second_key = 'token = "ghp_' + "Q7Zp4Xk9Lw2Md5FtR8bNc3Ve6Ha1Jq0Ks8Rt" + '"\n'
        (repo / "other.py").write_text(second_key, encoding="utf-8")
        commit_all(repo, "add second key")
        scan_2 = _run_and_record(repo, store, catalog, config, "2026-01-02T00:00:00+00:00")

        diff_12 = diff_scans(store, scan_1, scan_2)
        assert len(diff_12.new) == 1
        assert len(diff_12.persisting) == 1
        assert len(diff_12.resolved) == 0

        # Third scan: remove the original key entirely -- it should resolve.
        (repo / "app.py").write_text("# key removed\n", encoding="utf-8")
        commit_all(repo, "remove first key")
        scan_3 = _run_and_record(repo, store, catalog, config, "2026-01-03T00:00:00+00:00")

        diff_23 = diff_scans(store, scan_2, scan_3)
        assert len(diff_23.resolved) == 1
        assert len(diff_23.persisting) == 1
        assert len(diff_23.new) == 0

        rows = store.query_findings(status="resolved")
        assert len(rows) == 1
        rows_open = store.query_findings(status="open")
        assert len(rows_open) == 1


def test_allowlist_add_and_remove(tmp_path: Path):
    repo = tmp_path / "repo"
    init_git_repo(repo)
    (repo / "app.py").write_text('key = "AKIAQ7ZP4XKM9LWD2FTR"\n', encoding="utf-8")
    commit_all(repo, "initial key")

    catalog = load_catalog()
    config = ScannerConfig()
    db_path = tmp_path / "findings.db"

    with SqliteStore(db_path) as store:
        _run_and_record(repo, store, catalog, config, "2026-01-01T00:00:00+00:00")
        finding_id = store.query_findings()[0]["finding_id"]

        store.add_allowlist(finding_id, "known test fixture", "tester", "2026-01-01T00:00:00+00:00")
        assert store.query_findings(status="allowlisted")[0]["finding_id"] == finding_id
        assert len(store.list_allowlist()) == 1

        store.remove_allowlist(finding_id)
        assert store.query_findings(status="open")[0]["finding_id"] == finding_id
        assert len(store.list_allowlist()) == 0
