"""THE canary test. PLAN.md section 11.2 -- the only mechanism that catches
a future contributor adding a well-meaning `snippet`/`preview` field.

Plants structurally valid, PUBLICLY KNOWN-FAKE secrets, runs a full scan
through SQLite storage and every export format, then reads every produced
artifact back AS RAW BYTES and asserts each canary value appears ZERO
times anywhere. Also asserts the scan actually found them, proving this
is testing a populated corpus, not an empty one.
"""

from __future__ import annotations

from pathlib import Path

from apikey_scanner.catalog.loader import load_catalog
from apikey_scanner.config import ScannerConfig
from apikey_scanner.pipeline import run_scan
from apikey_scanner.report.structured import to_csv, to_json, to_jsonl
from apikey_scanner.report.table import to_table
from apikey_scanner.store.sqlite_store import SqliteStore
from .conftest import commit_all, init_git_repo

# Every value below is a publicly documented, known-fake example secret
# (AWS's own docs, Slack's own docs, Stripe's own docs) or a structurally
# valid but never-issued fake -- planted deliberately so this test can
# assert their exact bytes never survive into any output artifact.
CANARIES: dict[str, str] = {
    'aws_access_key_id': 'AKIAIOSFOD' + 'NN7EXAMPLE',
    'github_pat_classic': 'ghp_Q7Zp4Xk9Lw2Md5Ft' + 'R8bNc3Ve6Ha1Jq0Ks8Rt',
    'slack_bot_token': 'xoxb-1234567890-123456789' + '0-abcdefghijklmnopqrstuvwx',
    'stripe_live_secret_key': 'sk_live_Q7Zp4Xk9Lw2' + 'Md5FtR8bNc3Ve6Ha1Jq',
    'openai_api_key': 'sk-proj-Q7Zp4Xk9Lw2Md' + '5FtR8bNc3Ve6Ha1Jq0Ks9L',
}


def _plant_fixture_repo(repo: Path) -> None:
    init_git_repo(repo)
    lines = [f'{pattern_id}_value = "{value}"\n' for pattern_id, value in CANARIES.items()]
    (repo / "secrets_fixture.py").write_text("".join(lines), encoding="utf-8")
    commit_all(repo, "plant canaries")


def test_canary_values_never_appear_in_any_output_artifact(tmp_path: Path):
    repo = tmp_path / "canary_repo"
    _plant_fixture_repo(repo)

    catalog = load_catalog()
    config = ScannerConfig()
    findings, summary, scanned_repo_ids = run_scan([repo], catalog, config)

    # Sanity: prove this test is scanning a populated corpus, not an empty one.
    assert summary.findings_total >= len(CANARIES)
    found_pattern_ids = {f.pattern_id for f in findings}
    for pattern_id in CANARIES:
        assert pattern_id in found_pattern_ids, f"canary for {pattern_id} was not detected"

    db_path = tmp_path / "findings.db"
    with SqliteStore(db_path) as store:
        scan_id = store.start_scan(
            scan_timestamp="2026-01-01T00:00:00+00:00",
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

    artifacts: list[bytes] = [db_path.read_bytes()]
    artifacts.append(to_jsonl(findings).encode("utf-8"))
    artifacts.append(to_json(findings).encode("utf-8"))
    artifacts.append(to_csv(findings).encode("utf-8"))
    artifacts.append(to_table(findings).encode("utf-8"))

    for canary_value in CANARIES.values():
        for artifact in artifacts:
            assert canary_value.encode("utf-8") not in artifact, (
                f"CANARY LEAK: secret value found in an output artifact "
                f"(len={len(artifact)} bytes)"
            )
