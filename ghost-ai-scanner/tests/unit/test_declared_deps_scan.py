# =============================================================
# FILE: tests/unit/test_declared_deps_scan.py
# PROJECT: PatronAI — scanner graft
# VERSION: 1.0.0
# UPDATED: 2026-09-04
# OWNER: Giggso Inc
# PURPOSE: Lock scan_declared_deps.py.frag's contract (Phase 2 of the
#          scanner-graft plan):
#          - no companion installed (agent/scanners/ai_sdk_scanner
#            missing) -> [] (optional module)
#          - no repos discovered -> [] (nothing to scan)
#          - one ai_sdk_scanner record -> one declared_dependency
#            finding with the right fields
#          - --ai-only is always in the invoked command line
#          - a repo path reconstructed from path_safe never leaks the
#            real home dir into the emitted finding (repo_safe stays
#            the redacted form)
#          - a subprocess failure for one repo doesn't raise — it's
#            skipped, other repos still get scanned
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
    """Stand-in for `subprocess`. Records every call so tests can assert
    on the invoked command line; returns canned JSON or raises to
    simulate a scan failure."""
    DEVNULL = -1

    def __init__(self, envelope: dict | None = None, raise_for: set | None = None):
        self._envelope = envelope if envelope is not None else {"records": []}
        self._raise_for = raise_for or set()
        self.calls: list = []

    def check_output(self, args, **kwargs):
        self.calls.append(args)
        repo_arg = args[3] if len(args) > 3 else ""
        if repo_arg in self._raise_for:
            raise RuntimeError("scan failed")
        return json.dumps(self._envelope)


def _run_declared_deps_scan(home: Path, discovered_repos: list, fake_sp: _FakeSubprocess) -> list:
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
        for frag in ("scan_redactor.py.frag", "scan_declared_deps.py.frag"):
            exec(compile((FRAGS / frag).read_text(encoding="utf-8"), frag, "exec"), ns)
        return ns["scan_declared_deps"]()
    finally:
        Path.home = real_home  # type: ignore


def _repo_entry(home: Path, name: str) -> dict:
    repo_dir = home / "projects" / name
    repo_dir.mkdir(parents=True, exist_ok=True)
    return {"path_safe": f"~/projects/{name}", "name": name, "head_sha": "abc1234", "remote_host": "github.com"}


def test_no_companion_installed_means_no_findings(tmp_path):
    out = _run_declared_deps_scan(tmp_path, [_repo_entry(tmp_path, "repo1")], _FakeSubprocess())
    assert out == []


def test_no_repos_discovered_means_no_findings(tmp_path):
    (tmp_path / ".patronai" / "scanners" / "ai_sdk_scanner").mkdir(parents=True)
    out = _run_declared_deps_scan(tmp_path, [], _FakeSubprocess())
    assert out == []


def test_one_record_becomes_one_finding(tmp_path):
    (tmp_path / ".patronai" / "scanners" / "ai_sdk_scanner").mkdir(parents=True)
    repo = _repo_entry(tmp_path, "repo1")
    fake_sp = _FakeSubprocess({"records": [{
        "dependency_name": "langchain", "dependency_version": "0.3.1",
        "normalized_name": "langchain", "ecosystem": "python",
        "category": "llm_framework", "is_ai_related": True, "is_direct": True,
        "manifest_kind": "requirements.txt", "file_path": "requirements.txt",
        "line_number": 12,
    }]})
    out = _run_declared_deps_scan(tmp_path, [repo], fake_sp)
    assert len(out) == 1
    f = out[0]
    assert f["type"] == "declared_dependency"
    assert f["dependency_name"] == "langchain"
    assert f["is_ai_related"] is True
    assert f["repo_safe"] == "~/projects/repo1"


def test_ai_only_flag_always_passed(tmp_path):
    (tmp_path / ".patronai" / "scanners" / "ai_sdk_scanner").mkdir(parents=True)
    repo = _repo_entry(tmp_path, "repo1")
    fake_sp = _FakeSubprocess({"records": []})
    _run_declared_deps_scan(tmp_path, [repo], fake_sp)
    assert len(fake_sp.calls) == 1
    assert "--ai-only" in fake_sp.calls[0]
    assert "--format" in fake_sp.calls[0] and "json" in fake_sp.calls[0]


def test_repo_safe_never_carries_the_real_home_path(tmp_path):
    (tmp_path / ".patronai" / "scanners" / "ai_sdk_scanner").mkdir(parents=True)
    repo = _repo_entry(tmp_path, "repo1")
    fake_sp = _FakeSubprocess({"records": [{
        "dependency_name": "flask", "dependency_version": "3.0.0",
        "ecosystem": "python", "category": "web", "is_ai_related": False,
        "is_direct": True, "manifest_kind": "requirements.txt",
        "file_path": "requirements.txt", "line_number": 1,
    }]})
    out = _run_declared_deps_scan(tmp_path, [repo], fake_sp)
    assert str(tmp_path) not in json.dumps(out)


def test_one_repo_failing_does_not_abort_the_others(tmp_path):
    (tmp_path / ".patronai" / "scanners" / "ai_sdk_scanner").mkdir(parents=True)
    bad_repo = _repo_entry(tmp_path, "bad")
    good_repo = _repo_entry(tmp_path, "good")
    good_path = str(tmp_path / "projects" / "good")
    bad_path = str(tmp_path / "projects" / "bad")
    fake_sp = _FakeSubprocess({"records": [{
        "dependency_name": "openai", "dependency_version": "1.0.0",
        "ecosystem": "python", "category": "llm_sdk", "is_ai_related": True,
        "is_direct": True, "manifest_kind": "pyproject.toml",
        "file_path": "pyproject.toml", "line_number": 5,
    }]}, raise_for={bad_path})
    out = _run_declared_deps_scan(tmp_path, [bad_repo, good_repo], fake_sp)
    assert len(out) == 1
    assert out[0]["repo_safe"] == "~/projects/good"
