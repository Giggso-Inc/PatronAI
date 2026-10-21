"""Antitamper emit dedupe — same finding must not re-mail within TTL."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from antitamper import emit_dedupe as d


@pytest.fixture
def dedupe_home(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTITAMPER_DEDUPE_HOME", str(tmp_path / "dedupe"))
    return tmp_path / "dedupe"


def test_fingerprint_stable():
    a = d.fingerprint(
        product="patron", hostname="H1", event_type="DELETED",
        file_path="src/a.py", old_hash="aaa", new_hash=None,
    )
    b = d.fingerprint(
        product="patron", hostname="h1", event_type="deleted",
        file_path="src\\a.py", old_hash="aaa", new_hash=None,
    )
    assert a == b


def test_source_event_id_stable(dedupe_home):
    fp = d.fingerprint(
        product="patron", hostname="dev", event_type="MODIFIED",
        file_path="x.py", old_hash="1", new_hash="2",
    )
    assert d.source_event_id("patron", fp) == d.source_event_id("patron", fp)
    assert d.source_event_id("patron", fp).startswith("patron:tamper:")


def test_should_emit_once_per_ttl(dedupe_home):
    fp = d.fingerprint(
        product="patron", hostname="dev", event_type="DELETED",
        file_path="gone.py", old_hash="abc", new_hash=None,
    )
    assert d.should_emit(fp, home=dedupe_home) is True
    d.mark_emitted(fp, home=dedupe_home)
    assert d.should_emit(fp, home=dedupe_home) is False


def test_new_hash_is_new_fingerprint(dedupe_home):
    a = d.fingerprint(
        product="patron", hostname="dev", event_type="MODIFIED",
        file_path="x.py", old_hash="1", new_hash="2",
    )
    b = d.fingerprint(
        product="patron", hostname="dev", event_type="MODIFIED",
        file_path="x.py", old_hash="1", new_hash="3",
    )
    assert a != b
    d.mark_emitted(a, home=dedupe_home)
    assert d.should_emit(a, home=dedupe_home) is False
    assert d.should_emit(b, home=dedupe_home) is True


def test_handle_finding_skips_second_emit(tmp_path, monkeypatch):
    from antitamper import scanner as sc
    from unittest.mock import MagicMock, patch
    import json

    monkeypatch.setenv("ANTITAMPER_DEDUPE_HOME", str(tmp_path / "dd"))
    monkeypatch.setenv("RAVEN_HUB_URL", "http://hub.test")
    calls = []

    def fake_urlopen(req, timeout=8):
        calls.append(json.loads(req.data.decode()))
        return MagicMock()

    finding = {
        "file_path": "src/protected.py",
        "event_type": "DELETED",
        "old_hash": "deadbeef",
        "new_hash": None,
        "hostname": "HOST1",
        "user_email": "dev@corp.com",
        "restored": False,
        "restore_ok": False,
        "agent_version": "1.0.0",
    }
    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        sc._handle_finding(finding, org="giggso", persist=False, emit=True)
        sc._handle_finding(finding, org="giggso", persist=False, emit=True)

    assert len(calls) == 1
    assert calls[0]["alert_code"] == "patron_tamper"
    assert calls[0]["source_event_id"].startswith("patron:tamper:")
