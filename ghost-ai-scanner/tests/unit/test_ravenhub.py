# =============================================================
# FILE: tests/unit/test_ravenhub.py
# VERSION: 1.0.0
# UPDATED: 2026-07-20
# OWNER: Giggso Inc
# PURPOSE: Lock routers/ravenhub.py — the pure aggregation functions
#          (KPIs, Data Exposure, Risk Heatmap, AI Landscape) and the
#          server-side admin-resolution chain (DB -> S3 -> env),
#          including the deny-on-unknown-email 403 path. Pure; no
#          real S3/DB — identity resolvers are stubbed.
# =============================================================

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT))

from fastapi import HTTPException

from routers.ravenhub import (
    _kpis, _data_exposure, _risk_heatmap, _ai_landscape,
    _resolve_is_admin, _db_is_admin, _s3_is_admin, _env_is_admin,
)


def _ev(**kw) -> dict:
    """Build an event dict with sane defaults, overridable per test."""
    base = {
        "outcome": "ENDPOINT_FINDING", "severity": "MEDIUM",
        "provider": "claude.ai", "category": "browser", "department": "",
        "owner": "a@giggso.com", "email": "a@giggso.com",
        "timestamp": "2026-07-20T08:00:00Z", "geo_country": "", "bytes_out": 0,
    }
    base.update(kw)
    return base


# ── _kpis ──────────────────────────────────────────────────────

def test_kpis_counts_and_deltas():
    events = [
        _ev(outcome="ENDPOINT_FINDING", severity="HIGH", provider="claude.ai", category="browser"),
        _ev(outcome="ENDPOINT_FINDING", severity="MEDIUM", provider="chatgpt.com", category="package"),
        _ev(outcome="HEARTBEAT", severity="CLEAN", provider="", category=""),
    ]
    kpis = _kpis(events, y_summary={"total_events": 1, "by_severity": {"HIGH": 0}, "unique_providers": 1})
    assert kpis["ai_findings"] == {"value": 2, "delta": 1}
    assert kpis["high_severity"] == {"value": 1, "delta": 1}
    assert kpis["ai_providers_detected"] == {"value": 2, "delta": 1}
    assert kpis["categories_found"] == {"value": 2}
    assert kpis["alerts_fired"] == {"value": 2, "delta": 1}


def test_kpis_empty_events():
    kpis = _kpis([], y_summary={})
    assert kpis["ai_findings"] == {"value": 0, "delta": 0}
    assert kpis["categories_found"] == {"value": 0}


# ── _data_exposure ─────────────────────────────────────────────

def test_data_exposure_sankey_links_and_node_caps():
    events = [
        _ev(category="browser", provider="claude.ai"),
        _ev(category="browser", provider="claude.ai"),
        _ev(category="package", provider="pip:requests"),
        _ev(outcome="HEARTBEAT"),   # excluded — not "active"
        _ev(outcome="SUPPRESS"),    # excluded
        _ev(outcome="CLEAN"),       # excluded
    ]
    result = _data_exposure(events)
    sankey = result["sankey"]
    assert sankey["categories"] == ["browser", "package"]
    assert sankey["providers"] == ["claude.ai", "pip:requests"]
    assert {"from": "browser", "to": "claude.ai", "value": 2} in sankey["links"]
    assert {"from": "package", "to": "pip:requests", "value": 1} in sankey["links"]


def test_data_exposure_incidents_filters_severity_and_caps_at_15():
    events = (
        [_ev(severity="CRITICAL", email="c@giggso.com") for _ in range(10)]
        + [_ev(severity="HIGH", email="h@giggso.com") for _ in range(10)]
        + [_ev(severity="LOW")]  # excluded — not CRITICAL/HIGH
    )
    incidents = _data_exposure(events)["recent_incidents"]
    assert len(incidents) == 15
    assert all(i["severity"] in ("CRITICAL", "HIGH") for i in incidents)


# ── _risk_heatmap ──────────────────────────────────────────────

def test_risk_heatmap_matrix_and_row_fallback():
    events = [
        _ev(category="browser", severity="HIGH"),
        _ev(category="", department="", severity="MEDIUM"),   # falls back to "unknown"
    ]
    result = _risk_heatmap(events)
    heatmap = result["heatmap"]
    assert heatmap["columns"] == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    assert "unknown" in heatmap["rows"]
    assert "browser" in heatmap["rows"]
    browser_row = heatmap["matrix"][heatmap["rows"].index("browser")]
    assert browser_row == [0, 1, 0, 0]   # one HIGH, nothing else


def test_risk_heatmap_top_offenders_ranked_by_count_and_worst_severity():
    events = (
        [_ev(owner="heavy@giggso.com", severity="MEDIUM") for _ in range(5)]
        + [_ev(owner="light@giggso.com", severity="CRITICAL")]
        + [_ev(owner="heavy@giggso.com", severity="CRITICAL")]
    )
    top = _risk_heatmap(events)["top_offenders"]
    assert top[0]["owner"] == "heavy@giggso.com"
    assert top[0]["count"] == 6
    assert top[0]["severity"] == "CRITICAL"   # one CRITICAL among mostly MEDIUM still wins


# ── _ai_landscape ──────────────────────────────────────────────

def test_ai_landscape_world_map_and_provider_bubble():
    events = [
        _ev(geo_country="US", provider="claude.ai", bytes_out=100, severity="HIGH"),
        _ev(geo_country="US", provider="claude.ai", bytes_out=50, severity="LOW"),
        _ev(geo_country="IN", provider="chatgpt.com", bytes_out=0),
        _ev(outcome="SUPPRESS", geo_country="FR"),   # excluded everywhere
    ]
    result = _ai_landscape(events)
    assert result["world_map"] == {"US": 2, "IN": 1}
    bubble = {b["provider"]: b for b in result["provider_bubble"]}
    assert bubble["claude.ai"]["count"] == 2
    assert bubble["claude.ai"]["bytes_out"] == 150
    assert bubble["claude.ai"]["severity"] == "HIGH"   # worst severity kept, not overwritten by LOW


def test_ai_landscape_trend_30d_buckets_by_day_and_excludes_noise():
    events = [
        _ev(timestamp="2026-07-19T10:00:00Z"),
        _ev(timestamp="2026-07-19T11:00:00Z"),
        _ev(timestamp="2026-07-20T09:00:00Z"),
        _ev(outcome="HEARTBEAT", timestamp="2026-07-20T09:05:00Z"),  # excluded
        _ev(outcome="CLEAN", timestamp="2026-07-20T09:06:00Z"),      # excluded
    ]
    trend = {t["date"]: t["count"] for t in _ai_landscape(events)["trend_30d"]}
    assert trend == {"2026-07-19": 2, "2026-07-20": 1}


# ── _resolve_is_admin: DB -> S3 -> env chain ────────────────────

class _FakeUser:
    def __init__(self, is_org_admin: bool):
        self.is_org_admin = is_org_admin


class _FakeScalarResult:
    def __init__(self, user):
        self._user = user
    def scalar_one_or_none(self):
        return self._user


class _FakeSession:
    """Minimal stand-in for a SQLAlchemy Session context manager."""
    def __init__(self, user):
        self._user = user
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False
    def execute(self, *_a, **_kw):
        return _FakeScalarResult(self._user)


def test_db_is_admin_returns_none_without_database_url(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert _db_is_admin("x@giggso.com") is None


def test_db_is_admin_true_for_org_admin(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://fake")
    import db.engine as engine_mod
    monkeypatch.setattr(engine_mod, "get_session", lambda: _FakeSession(_FakeUser(True)))
    assert _db_is_admin("admin@giggso.com") is True


def test_db_is_admin_false_for_non_admin(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://fake")
    import db.engine as engine_mod
    monkeypatch.setattr(engine_mod, "get_session", lambda: _FakeSession(_FakeUser(False)))
    assert _db_is_admin("dev@giggso.com") is False


def test_db_is_admin_none_when_user_not_found(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://fake")
    import db.engine as engine_mod
    monkeypatch.setattr(engine_mod, "get_session", lambda: _FakeSession(None))
    assert _db_is_admin("nobody@giggso.com") is None


def test_db_is_admin_none_on_exception(monkeypatch):
    """A DB outage must fall through to S3/env, not raise or deny outright."""
    monkeypatch.setenv("DATABASE_URL", "postgresql://fake")
    import db.engine as engine_mod
    def _boom():
        raise RuntimeError("connection refused")
    monkeypatch.setattr(engine_mod, "get_session", _boom)
    assert _db_is_admin("x@giggso.com") is None


class _FakeUsersStore:
    def __init__(self, records: dict):
        self._records = records
    def get(self, email):
        return self._records.get(email)
    def read_all(self):
        return self._records


def test_s3_is_admin_none_without_bucket(monkeypatch):
    monkeypatch.delenv("MARAUDER_SCAN_BUCKET", raising=False)
    assert _s3_is_admin("x@giggso.com") is None


def test_s3_is_admin_true_for_recorded_admin(monkeypatch):
    monkeypatch.setenv("MARAUDER_SCAN_BUCKET", "fake-bucket")
    import store.users_store as users_store_mod
    records = {"admin@giggso.com": {"is_admin": True}}
    monkeypatch.setattr(users_store_mod, "UsersStore", lambda *a, **kw: _FakeUsersStore(records))
    assert _s3_is_admin("admin@giggso.com") is True


def test_s3_is_admin_denies_when_store_populated_but_email_absent(monkeypatch):
    monkeypatch.setenv("MARAUDER_SCAN_BUCKET", "fake-bucket")
    import store.users_store as users_store_mod
    records = {"someone-else@giggso.com": {"is_admin": True}}
    monkeypatch.setattr(users_store_mod, "UsersStore", lambda *a, **kw: _FakeUsersStore(records))
    with pytest.raises(HTTPException) as exc:
        _s3_is_admin("unknown@giggso.com")
    assert exc.value.status_code == 403


def test_s3_is_admin_none_when_store_empty(monkeypatch):
    """Empty store (never migrated) falls through to env, not a 403."""
    monkeypatch.setenv("MARAUDER_SCAN_BUCKET", "fake-bucket")
    import store.users_store as users_store_mod
    monkeypatch.setattr(users_store_mod, "UsersStore", lambda *a, **kw: _FakeUsersStore({}))
    assert _s3_is_admin("anyone@giggso.com") is None


def test_env_is_admin_true_for_admin_emails(monkeypatch):
    monkeypatch.setenv("ADMIN_EMAILS", "dev@giggso.com")
    monkeypatch.setenv("ALLOWED_EMAILS", "")
    assert _env_is_admin("dev@giggso.com") is True


def test_env_is_admin_false_for_allowed_emails(monkeypatch):
    monkeypatch.setenv("ADMIN_EMAILS", "")
    monkeypatch.setenv("ALLOWED_EMAILS", "dev@giggso.com")
    assert _env_is_admin("dev@giggso.com") is False


def test_env_is_admin_denies_unknown_email(monkeypatch):
    monkeypatch.setenv("ADMIN_EMAILS", "dev@giggso.com")
    monkeypatch.setenv("ALLOWED_EMAILS", "")
    with pytest.raises(HTTPException) as exc:
        _env_is_admin("random-unknown@giggso.com")
    assert exc.value.status_code == 403


def test_resolve_is_admin_db_wins_over_s3_and_env(monkeypatch):
    """DB is checked first — a stale S3/env entry must not override it."""
    monkeypatch.setenv("DATABASE_URL", "postgresql://fake")
    import db.engine as engine_mod
    monkeypatch.setattr(engine_mod, "get_session", lambda: _FakeSession(_FakeUser(True)))
    # If DB weren't checked first, this conflicting S3 record would flip the result.
    monkeypatch.setenv("MARAUDER_SCAN_BUCKET", "fake-bucket")
    import store.users_store as users_store_mod
    monkeypatch.setattr(users_store_mod, "UsersStore",
                         lambda *a, **kw: _FakeUsersStore({"admin@giggso.com": {"is_admin": False}}))
    assert _resolve_is_admin("admin@giggso.com") is True


def test_resolve_is_admin_falls_back_to_s3_when_db_unavailable(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("MARAUDER_SCAN_BUCKET", "fake-bucket")
    import store.users_store as users_store_mod
    monkeypatch.setattr(users_store_mod, "UsersStore",
                         lambda *a, **kw: _FakeUsersStore({"exec@giggso.com": {"is_admin": True}}))
    assert _resolve_is_admin("exec@giggso.com") is True


def test_resolve_is_admin_denies_unknown_email_everywhere(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("MARAUDER_SCAN_BUCKET", raising=False)
    monkeypatch.setenv("ADMIN_EMAILS", "dev@giggso.com")
    monkeypatch.setenv("ALLOWED_EMAILS", "")
    with pytest.raises(HTTPException) as exc:
        _resolve_is_admin("totally-unknown@giggso.com")
    assert exc.value.status_code == 403
