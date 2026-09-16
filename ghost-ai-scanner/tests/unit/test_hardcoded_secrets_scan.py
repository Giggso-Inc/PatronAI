# =============================================================
# FILE: tests/unit/test_hardcoded_secrets_scan.py
# PROJECT: PatronAI — scanner graft
# VERSION: 1.0.0
# UPDATED: 2026-09-04
# OWNER: Giggso Inc
# PURPOSE: Lock scan_hardcoded_secrets.py.frag's contract (Phase 2 of
#          the scanner-graft plan):
#          - no companion installed -> [] (optional module)
#          - no repos discovered -> [] (nothing to scan; `scan`/
#            `report` are never invoked)
#          - one jsonl finding line -> one hardcoded_secret finding,
#            with repo_safe (not the real path) and no secret value
#            anywhere in the output — apikey-scanner's own Finding
#            model has no field for the secret bytes, so there is
#            nothing to redact away here; this test exists so a
#            future field addition upstream can't accidentally add one
#            without this test catching it
#          - every `scan`/`report` call passes an explicit --db under
#            a throwaway tempdir — never the tool's own
#            .apikey-scanner/findings.db default
#          - a scan/report subprocess failure returns [] rather than
#            raising
# AUDIT LOG:
#   v1.0.0  2026-09-04  Initial.
# =============================================================

import json
import os
import re
from pathlib import Path

REPO  = Path(__file__).resolve().parents[2]
FRAGS = REPO / "agent" / "install"


class _FakeSubprocess:
    DEVNULL = -1

    def __init__(self, report_jsonl: str = "", raise_on_scan: bool = False, raise_on_report: bool = False):
        self._report_jsonl = report_jsonl
        self._raise_on_scan = raise_on_scan
        self._raise_on_report = raise_on_report
        self.calls: list = []

    def check_output(self, args, **kwargs):
        self.calls.append(args)
        if "scan" in args:
            if self._raise_on_scan:
                raise RuntimeError("scan failed")
            return ""
        if "report" in args:
            if self._raise_on_report:
                raise RuntimeError("report failed")
            return self._report_jsonl
        raise AssertionError(f"unexpected subprocess call: {args}")


def _run_hardcoded_secrets_scan(home: Path, discovered_repos: list, fake_sp: _FakeSubprocess) -> list:
    ns: dict = {
        "re": re, "Path": Path, "os": os, "json": json,
        "subprocess": fake_sp,
        "OS_NAME": "darwin",
        "AGENT_DIR": home / ".patronai",
        "DISCOVERED_REPOS": discovered_repos,
    }
    real_home = Path.home
    Path.home = staticmethod(lambda: home)  # type: ignore
    try:
        for frag in ("scan_redactor.py.frag", "scan_hardcoded_secrets.py.frag"):
            exec(compile((FRAGS / frag).read_text(encoding="utf-8"), frag, "exec"), ns)
        return ns["scan_hardcoded_secrets"]()
    finally:
        Path.home = real_home  # type: ignore


def _repo_entry(home: Path, name: str) -> dict:
    repo_dir = home / "projects" / name
    repo_dir.mkdir(parents=True, exist_ok=True)
    return {"path_safe": f"~/projects/{name}", "name": name, "head_sha": "abc1234", "remote_host": "github.com"}


def _install_companion(home: Path) -> None:
    (home / ".patronai" / "scanners" / "apikey_scanner").mkdir(parents=True)


def _finding_line(**overrides) -> str:
    base = {
        "repo_id": "repo1", "repo_path": "", "file_path": "config/settings.py",
        "line_number": 14, "column_start": 10, "match_length": 51,
        "matched_pattern_type": "aws_access_key_id", "pattern_id": "aws-akid",
        "provider": "aws", "confidence": "high", "detector": "regex",
        "entropy_bits": None, "commit_sha": "deadbeef", "author_name": "Alice Dev",
        "author_email": "alice@example.com", "author_timestamp": "2026-09-01T00:00:00Z",
        "provenance_state": "committed", "is_git_tracked": True,
        "is_gitignored": False, "in_test_path": False,
        "scan_timestamp": "2026-09-04T00:00:00Z", "secret_fingerprint": "sha256:abc123",
    }
    base.update(overrides)
    return json.dumps(base)


def test_no_companion_installed_means_no_findings(tmp_path):
    out = _run_hardcoded_secrets_scan(tmp_path, [_repo_entry(tmp_path, "repo1")], _FakeSubprocess())
    assert out == []


def test_no_repos_discovered_means_no_subprocess_calls(tmp_path):
    _install_companion(tmp_path)
    fake_sp = _FakeSubprocess()
    out = _run_hardcoded_secrets_scan(tmp_path, [], fake_sp)
    assert out == []
    assert fake_sp.calls == []


def test_one_finding_line_becomes_one_finding(tmp_path):
    _install_companion(tmp_path)
    repo = _repo_entry(tmp_path, "repo1")
    repo_path_real = str(tmp_path / "projects" / "repo1")
    fake_sp = _FakeSubprocess(report_jsonl=_finding_line(repo_path=repo_path_real))
    out = _run_hardcoded_secrets_scan(tmp_path, [repo], fake_sp)
    assert len(out) == 1
    f = out[0]
    assert f["type"] == "hardcoded_secret"
    assert f["provider"] == "aws"
    assert f["confidence"] == "high"
    assert f["repo_safe"] == "~/projects/repo1"
    assert f["blame_author"] == "Alice Dev"


def test_no_secret_value_field_anywhere_in_output(tmp_path):
    """apikey-scanner's Finding model carries no secret bytes at all —
    this is a regression tripwire, not a redaction test: if a future
    upstream change adds one, this test's dump-and-scan catches it."""
    _install_companion(tmp_path)
    repo = _repo_entry(tmp_path, "repo1")
    repo_path_real = str(tmp_path / "projects" / "repo1")
    fake_sp = _FakeSubprocess(report_jsonl=_finding_line(repo_path=repo_path_real))
    out = _run_hardcoded_secrets_scan(tmp_path, [repo], fake_sp)
    dumped = json.dumps(out)
    assert "secret_value" not in dumped
    assert "secret_bytes" not in dumped


def test_db_path_is_always_an_explicit_tempdir_path(tmp_path):
    _install_companion(tmp_path)
    repo = _repo_entry(tmp_path, "repo1")
    fake_sp = _FakeSubprocess(report_jsonl="")
    _run_hardcoded_secrets_scan(tmp_path, [repo], fake_sp)
    assert len(fake_sp.calls) == 2
    for call in fake_sp.calls:
        assert "--db" in call
        db_idx = call.index("--db")
        db_path = call[db_idx + 1]
        assert db_path != ".apikey-scanner/findings.db"
        assert "findings.db" in db_path


def test_scan_failure_returns_empty_not_raise(tmp_path):
    _install_companion(tmp_path)
    repo = _repo_entry(tmp_path, "repo1")
    fake_sp = _FakeSubprocess(raise_on_scan=True)
    out = _run_hardcoded_secrets_scan(tmp_path, [repo], fake_sp)
    assert out == []


def test_report_failure_returns_empty_not_raise(tmp_path):
    _install_companion(tmp_path)
    repo = _repo_entry(tmp_path, "repo1")
    fake_sp = _FakeSubprocess(raise_on_report=True)
    out = _run_hardcoded_secrets_scan(tmp_path, [repo], fake_sp)
    assert out == []


def test_malformed_jsonl_line_is_skipped_not_raised(tmp_path):
    _install_companion(tmp_path)
    repo = _repo_entry(tmp_path, "repo1")
    repo_path_real = str(tmp_path / "projects" / "repo1")
    good_line = _finding_line(repo_path=repo_path_real)
    fake_sp = _FakeSubprocess(report_jsonl="not json\n" + good_line)
    out = _run_hardcoded_secrets_scan(tmp_path, [repo], fake_sp)
    assert len(out) == 1
