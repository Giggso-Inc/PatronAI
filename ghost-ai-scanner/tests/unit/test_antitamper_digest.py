"""Unit tests for 60-minute antitamper burst digest."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from types import ModuleType, SimpleNamespace

from antitamper.digest import build_summary, maybe_emit_burst_digest


def test_build_summary_counts_and_paths():
    now = datetime.now(timezone.utc)
    rows = [
        SimpleNamespace(
            tamper_id="a",
            timestamp=now - timedelta(minutes=50),
            event_type="MODIFIED",
            file_path="src/a.py",
            user_email="a.kathijaafrose@giggso.com",
        ),
        SimpleNamespace(
            tamper_id="b",
            timestamp=now - timedelta(minutes=10),
            event_type="DELETED",
            file_path="src/b.py",
            user_email="a.kathijaafrose@giggso.com",
        ),
        SimpleNamespace(
            tamper_id="c",
            timestamp=now - timedelta(minutes=5),
            event_type="MODIFIED",
            file_path="src/a.py",
            user_email="a.kathijaafrose@giggso.com",
        ),
    ]
    s = build_summary(rows)
    assert s["count"] == 3
    assert "MODIFIED×2" in s["breakdown"]
    assert "DELETED×1" in s["breakdown"]
    assert "src/a.py" in s["file_path"]
    assert "src/b.py" in s["file_path"]
    assert s["user_email"] == "a.kathijaafrose@giggso.com"


class _Col:
    def asc(self):
        return self

    def is_(self, *_a, **_k):
        return self

    def in_(self, *_a, **_k):
        return self


def _install_db_stub(rows, *, updated=None):
    class _Q:
        def filter(self, *_a, **_k):
            return self

        def order_by(self, *_a, **_k):
            return self

        def limit(self, *_a, **_k):
            return self

        def all(self):
            return list(rows)

        def update(self, *_a, **_k):
            if updated is not None:
                updated["n"] += 1
            return len(rows)

    class _Sess:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def query(self, *_a, **_k):
            return _Q()

        def commit(self):
            return None

    dbm = ModuleType("db")
    dbm.get_session = lambda: _Sess()
    mm = ModuleType("db.models_antitamper")

    class AntitamperEvent:
        hostname = _Col()
        digest_emitted = _Col()
        timestamp = _Col()
        tamper_id = _Col()

    mm.AntitamperEvent = AntitamperEvent
    sys.modules["db"] = dbm
    sys.modules["db.models_antitamper"] = mm


def test_maybe_emit_skips_when_too_few():
    now = datetime.now(timezone.utc)
    _install_db_stub(
        [
            SimpleNamespace(
                tamper_id="only",
                timestamp=now - timedelta(hours=2),
                event_type="MODIFIED",
                file_path="x.py",
                user_email="dev@giggso.com",
            )
        ]
    )
    assert maybe_emit_burst_digest(hostname="host1", org="giggso", min_events=2) is None


def test_maybe_emit_digest_when_burst_ready():
    now = datetime.now(timezone.utc)
    rows = [
        SimpleNamespace(
            tamper_id="id1",
            timestamp=now - timedelta(minutes=65),
            event_type="MODIFIED",
            file_path="a.py",
            user_email="a.kathijaafrose@giggso.com",
        ),
        SimpleNamespace(
            tamper_id="id2",
            timestamp=now - timedelta(minutes=20),
            event_type="ADDED",
            file_path="b.py",
            user_email="a.kathijaafrose@giggso.com",
        ),
    ]
    updated = {"n": 0}
    _install_db_stub(rows, updated=updated)

    calls = []
    # Do not replace the real notify package — only stub hub_alerts attribute path
    # used by digest via `from notify.hub_alerts import emit_tamper_digest`.
    import notify.hub_alerts as hub_alerts

    original = getattr(hub_alerts, "emit_tamper_digest", None)

    def _fake_emit(*a, **k):
        calls.append(k)
        return True

    hub_alerts.emit_tamper_digest = _fake_emit  # type: ignore[attr-defined]
    try:
        summary = maybe_emit_burst_digest(
            hostname="KATHIJA-LAPTOP",
            org="giggso",
            user_email="a.kathijaafrose@giggso.com",
            digest_after_sec=3600,
            min_events=2,
        )
    finally:
        if original is not None:
            hub_alerts.emit_tamper_digest = original
        elif hasattr(hub_alerts, "emit_tamper_digest"):
            # leave the real function we added
            pass

    assert summary is not None
    assert summary["count"] == 2
    assert calls
    assert updated["n"] == 1
