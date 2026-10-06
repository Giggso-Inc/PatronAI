"""Unit tests for Patron antitamper scanner (no DB)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from antitamper import scanner as sc


@pytest.fixture
def install_tree(tmp_path, monkeypatch):
    root = tmp_path / "install"
    root.mkdir()
    (root / "VERSION").write_text("1.0.0-test", encoding="utf-8")
    (root / "src").mkdir()
    target = root / "src" / "protected.py"
    target.write_text("SAFE = True\n", encoding="utf-8")
    (root / "src" / "notify").mkdir()
    (root / "src" / "notify" / "hub_alerts.py").write_text("EMIT = 1\n", encoding="utf-8")

    home = tmp_path / "at-home"
    monkeypatch.setenv("PATRON_INSTALL_ROOT", str(root))
    monkeypatch.setenv("PATRON_ANTITAMPER_HOME", str(home))
    monkeypatch.setenv("RAVEN_AGENT_KEY", "test-token-for-hmac")
    # Reload module paths bound at import time
    sc.INSTALL_ROOT = root
    sc.BASELINE_ROOT = home / "baseline"
    return root, target


def test_baseline_then_clean_scan(install_tree):
    sc.build_baseline()
    _d, manifest, sig_ok = sc.load_baseline()
    assert sig_ok
    assert sc.scan(manifest) == []


def test_modified_file_detected_and_restored(install_tree):
    root, target = install_tree
    sc.build_baseline()
    target.write_text("SAFE = False\n", encoding="utf-8")
    findings = sc.run_once(persist=False, emit=False, restore_enabled=True)
    types = {f["event_type"] for f in findings}
    assert "MODIFIED" in types
    assert target.read_text(encoding="utf-8") == "SAFE = True\n"


def test_deleted_file_restored(install_tree):
    root, target = install_tree
    sc.build_baseline()
    target.unlink()
    findings = sc.run_once(persist=False, emit=False, restore_enabled=True)
    assert any(f["event_type"] == "DELETED" for f in findings)
    assert target.is_file()
    assert target.read_text(encoding="utf-8") == "SAFE = True\n"


def test_missing_baseline_is_base_fail(install_tree):
    findings = sc.run_once(persist=False, emit=False)
    assert findings and findings[0]["event_type"] == "BASE_FAIL"


def test_baseline_sig_break_reported(install_tree):
    d = sc.build_baseline()
    (d / "manifest.json").write_text(
        (d / "manifest.json").read_text(encoding="utf-8").replace("1.0.0", "9.9.9"),
        encoding="utf-8",
    )
    _d, _m, sig_ok = sc.load_baseline()
    assert not sig_ok
    findings = sc.run_once(persist=False, emit=False)
    assert findings[0]["event_type"] == "BASE_FAIL"
