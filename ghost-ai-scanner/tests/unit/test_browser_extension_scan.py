# =============================================================
# FILE: tests/unit/test_browser_extension_scan.py
# PROJECT: PatronAI — scanner graft
# VERSION: 1.0.0
# UPDATED: 2026-09-04
# OWNER: Giggso Inc
# PURPOSE: Lock scan_browser_extensions.py.frag's contract (Phase 2 of
#          the scanner-graft plan):
#          - no companion installed -> [] (optional module)
#          - one envelope["extensions"] record -> one
#            browser_extension finding
#          - --risk and --no-state are always in the invoked command
#            line
#          - "high_privilege_host_access" in the tool's own warnings[]
#            surfaces as a boolean field, not buried in a blob
#          - a malformed/non-JSON response doesn't raise — returns []
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

    def __init__(self, output: str | None = None):
        self._output = output if output is not None else json.dumps({"extensions": []})
        self.calls: list = []

    def check_output(self, args, **kwargs):
        self.calls.append(args)
        return self._output


def _run_browser_ext_scan(home: Path, fake_sp: _FakeSubprocess) -> list:
    ns: dict = {
        "re": re, "Path": Path, "os": os, "json": json,
        "subprocess": fake_sp,
        "OS_NAME": "darwin",
        "AGENT_DIR": home / ".patronai",
    }
    for frag in ("scan_redactor.py.frag", "scan_browser_extensions.py.frag"):
        exec(compile((FRAGS / frag).read_text(encoding="utf-8"), frag, "exec"), ns)
    return ns["scan_browser_extensions"]()


def _install_companion(home: Path) -> None:
    (home / ".patronai" / "scanners" / "extension_searcher").mkdir(parents=True)


def test_no_companion_installed_means_no_findings(tmp_path):
    out = _run_browser_ext_scan(tmp_path, _FakeSubprocess())
    assert out == []


def test_one_record_becomes_one_finding(tmp_path):
    _install_companion(tmp_path)
    fake_sp = _FakeSubprocess(json.dumps({"extensions": [{
        "extension_id": "abcdefghijklmnop", "name": "Grammarly",
        "version": "8.1.0", "browser": "Google Chrome",
        "profile_name": "Default", "enabled": True,
        "install_origin": "web_store",
        "host_permissions": ["<all_urls>"], "permissions": ["storage"],
        "warnings": ["high_privilege_host_access"],
    }]}))
    out = _run_browser_ext_scan(tmp_path, fake_sp)
    assert len(out) == 1
    f = out[0]
    assert f["type"] == "browser_extension"
    assert f["name"] == "Grammarly"
    assert f["browser"] == "Google Chrome"
    assert f["high_privilege_host_access"] is True


def test_no_risk_warning_means_flag_is_false(tmp_path):
    _install_companion(tmp_path)
    fake_sp = _FakeSubprocess(json.dumps({"extensions": [{
        "extension_id": "x", "name": "uBlock Origin", "version": "1.0",
        "browser": "Mozilla Firefox", "profile_name": "default-release",
        "enabled": True, "install_origin": "web_store",
        "host_permissions": [], "permissions": [], "warnings": [],
    }]}))
    out = _run_browser_ext_scan(tmp_path, fake_sp)
    assert out[0]["high_privilege_host_access"] is False


def test_risk_and_no_state_flags_always_passed(tmp_path):
    _install_companion(tmp_path)
    fake_sp = _FakeSubprocess()
    _run_browser_ext_scan(tmp_path, fake_sp)
    assert len(fake_sp.calls) == 1
    assert "--risk" in fake_sp.calls[0]
    assert "--no-state" in fake_sp.calls[0]


def test_malformed_output_returns_empty_not_raise(tmp_path):
    _install_companion(tmp_path)
    fake_sp = _FakeSubprocess("not json at all {{{")
    out = _run_browser_ext_scan(tmp_path, fake_sp)
    assert out == []
