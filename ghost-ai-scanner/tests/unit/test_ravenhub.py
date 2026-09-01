# =============================================================
# FILE: tests/unit/test_ravenhub.py
# VERSION: 1.5.0
# UPDATED: 2026-08-12
# OWNER: Giggso Inc
# PURPOSE: Lock routers/ravenhub.py — the pure aggregation functions
#          (KPIs, Data Exposure, Risk Heatmap, AI Landscape, AI Posture,
#          Asset Inventory, user logs), the server-side admin-resolution
#          chain (DB -> S3 -> env) incl. the deny-on-unknown-email 403
#          path, and the privilege gates on /inventory/overview
#          (admin-only) and /user/detail (admin-or-self) — both return
#          200 with no data rather than an error status when denied.
#          Pure; no real S3/DB — everything is stubbed.
#          Caller-identity JWT coverage (_verify_ravenhub_identity) now
#          lives in test_raven_identity.py, alongside the module it
#          moved to (routers/_raven_identity.py, v1.5.0).
# AUDIT LOG:
#   v1.0.0  2026-07-20  /exec/overview coverage.
#   v1.1.0  2026-07-20  /inventory/overview coverage (AI Posture,
#                       Asset Inventory, admin-only gate).
#   v1.2.0  2026-07-20  /user/detail coverage (user logs, admin-or-self
#                       gate).
#   v1.3.0  2026-07-21  _verify_ravenhub_identity coverage (PR#9 review,
#                       C1) — missing/invalid/expired token, wrong
#                       signing secret, missing email claim, secret not
#                       configured, valid-token happy path.
#   v1.4.0  2026-07-21  Moved _verify_ravenhub_identity coverage to
#                       test_raven_identity.py (function extracted to
#                       routers/_raven_identity.py in ravenhub.py v1.5.0).
#   v1.5.0  2026-08-12  test_kpis_counts_and_deltas updated for
#                       ravenhub.py v1.6.0's two _kpis() bug fixes
#                       (alerts_fired no longer duplicates ai_findings;
#                       ai_findings' delta compares findings-vs-findings
#                       instead of findings-vs-total_events).
# =============================================================

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT))

from fastapi import HTTPException

import routers.ravenhub as ravenhub
from routers.ravenhub import (
    _kpis, _data_exposure, _risk_heatmap, _ai_landscape,
    _resolve_is_admin, _db_is_admin, _s3_is_admin, _env_is_admin,
    _asset_key, _owner_of, _ai_posture, _asset_inventory,
    get_inventory_overview, InventoryOverviewResponse,
    _user_logs, get_user_detail, UserDetailResponse,
    _shadow_by_tool,
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
        _ev(outcome="DOMAIN_ALERT", severity="HIGH", provider="claude.ai", category="browser"),
        _ev(outcome="PORT_ALERT", severity="MEDIUM", provider="claude.ai", category=""),
        _ev(outcome="HEARTBEAT", severity="CLEAN", provider="", category=""),
    ]
    kpis = _kpis(events, y_summary={
        "total_events": 1, "by_severity": {"HIGH": 0},
        "by_outcome": {"ENDPOINT_FINDING": 5, "DOMAIN_ALERT": 2, "PORT_ALERT": 1},
        "unique_providers": 1, "alerts_fired": 0,
    })
    # delta compares today's ENDPOINT_FINDING count against yesterday's
    # ENDPOINT_FINDING count (by_outcome), not yesterday's total_events —
    # total_events (1) would give a different, wrong delta if this regresses.
    assert kpis["ai_findings"] == {"value": 2, "delta": -3}
    assert kpis["high_severity"] == {"value": 2, "delta": 2}
    assert kpis["ai_providers_detected"] == {"value": 2, "delta": 1}
    assert kpis["categories_found"] == {"value": 2}
    # alerts_fired counts ENDPOINT_FINDING/DOMAIN_ALERT/PORT_ALERT (matches
    # ingestor._stats()'s definition) — endpoint-only tenants with no
    # DOMAIN_ALERT/PORT_ALERT source would otherwise always read 0.
    # value: 2 ENDPOINT_FINDING + 1 DOMAIN_ALERT + 1 PORT_ALERT = 4
    # reference: 5 + 2 + 1 = 8 -> delta -4
    assert kpis["alerts_fired"] == {"value": 4, "delta": -4}


def test_kpis_empty_events():
    kpis = _kpis([], y_summary={})
    assert kpis["ai_findings"] == {"value": 0, "delta": 0}
    assert kpis["categories_found"] == {"value": 0}


# ── ai_providers_detected vs. Shadow AI Detection page's total_tools ────────
# GSD ticket "Shadow AI Detection - Metric Definition and Data Mapping": the
# Exec Overview widget's "Active Shadow Tools" (_kpis' ai_providers_detected)
# and the Shadow AI Detection page's "AI Providers Detected" (_shadow_by_tool's
# total_tools) are two different renderings of the same claim over the same
# event set and must never disagree.

def test_ai_providers_detected_always_matches_shadow_by_tool_total_tools():
    """The core reconciliation the ticket asked for, run over a mix that
    exercises both ways the two used to diverge in one event set."""
    events = [
        _ev(provider="claude.ai"),
        _ev(provider="chatgpt.com"),
        _ev(provider="claude.ai"),  # duplicate provider, not a new tool
    ]
    kpis = _kpis(events, y_summary={})
    assert kpis["ai_providers_detected"]["value"] == _shadow_by_tool(events)["total_tools"]
    assert kpis["ai_providers_detected"]["value"] == 2


def test_ai_providers_detected_excludes_resolved_findings():
    """The regression: a resolved finding used to still count here even
    though _shadow_by_tool had already excluded it, so resolving a shadow-AI
    finding dropped 'Active Shadow Tools' but left 'AI Providers Detected'
    unchanged."""
    events = [
        _ev(provider="claude.ai"),
        _ev(provider="chatgpt.com", status="resolved"),
    ]
    kpis = _kpis(events, y_summary={})
    assert kpis["ai_providers_detected"]["value"] == 1
    assert kpis["ai_providers_detected"]["value"] == _shadow_by_tool(events)["total_tools"]


def test_ai_providers_detected_counts_dst_domain_fallback_tools():
    """The other regression: a network detection with no resolved `provider`
    but a real `dst_domain` used to be invisible here while _shadow_by_tool
    already counted it via _tool_name_of's fallback."""
    events = [
        _ev(provider="claude.ai"),
        _ev(provider="", dst_domain="sketchy-ai-tool.example.com"),
    ]
    kpis = _kpis(events, y_summary={})
    assert kpis["ai_providers_detected"]["value"] == 2
    assert kpis["ai_providers_detected"]["value"] == _shadow_by_tool(events)["total_tools"]


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


# ── _asset_key / _owner_of ──────────────────────────────────────

def test_asset_key_prefers_device_id_then_hostname_then_ip():
    assert _asset_key({"device_id": "d1", "src_hostname": "h1", "src_ip": "1.1.1.1"}) == "d1"
    assert _asset_key({"src_hostname": "h1", "src_ip": "1.1.1.1"}) == "h1"
    assert _asset_key({"src_ip": "1.1.1.1"}) == "1.1.1.1"
    assert _asset_key({}) == "unknown"


def test_owner_of_prefers_email_over_owner():
    assert _owner_of({"email": "e@x.com", "owner": "o@x.com"}) == "e@x.com"
    assert _owner_of({"owner": "o@x.com"}) == "o@x.com"
    assert _owner_of({}) == ""


# ── _ai_posture (policy-blind — DATABASE_URL unset) ─────────────

def test_ai_posture_fleet_score_and_breakdown(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    events = (
        [_ev(src_hostname="dev-a", category="browser", severity="HIGH", outcome="ENDPOINT_FINDING")]
        + [_ev(src_hostname="dev-b", category="package", severity="LOW", outcome="ENDPOINT_FINDING")]
    )
    posture = _ai_posture(events)
    assert posture["device_label"] == "2 devices"
    assert set(posture["device_scores"].keys()) == {"dev-a", "dev-b"}
    assert posture["score"] > 0
    cats = {b["category"] for b in posture["breakdown"]}
    assert cats == {"browser", "package"}


def test_ai_posture_single_device_label(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    events = [_ev(src_hostname="solo-box")]
    posture = _ai_posture(events)
    assert posture["device_label"] == "solo-box"


def test_ai_posture_empty_events_scores_zero(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    posture = _ai_posture([])
    assert posture["score"] == 0
    assert posture["band"] == "CLEAN"
    assert posture["breakdown"] == []


# ── _asset_inventory ─────────────────────────────────────────────

def test_asset_inventory_ranks_by_count_and_reports_fields():
    events = (
        [_ev(src_hostname="busy-box", owner="a@giggso.com", asset_type="laptop",
             mac_address="aa:bb", severity="HIGH") for _ in range(5)]
        + [_ev(src_hostname="quiet-box", owner="b@giggso.com", asset_type="ec2",
               severity="LOW")]
    )
    rows = _asset_inventory(events, dev_score={"busy-box": 50, "quiet-box": 5})
    assert rows[0]["asset_key"] == "busy-box"
    assert rows[0]["events"] == 5
    assert rows[0]["owner"] == "a@giggso.com"
    assert rows[0]["type"] == "laptop"
    assert rows[0]["mac"] == "aa:bb"
    assert rows[0]["score"] == 50
    assert rows[0]["status"] == "HIGH"   # CRITICAL_AT=75, HIGH_AT=40 (scoring_weights.py)
    assert rows[1]["asset_key"] == "quiet-box"


def test_asset_inventory_caps_at_limit():
    events = [_ev(src_hostname=f"box-{i}") for i in range(25)]
    rows = _asset_inventory(events, dev_score={}, limit=20)
    assert len(rows) == 20


def test_asset_inventory_zero_events_asset_is_clean_status():
    events = [_ev(src_hostname="box", outcome="SUPPRESS")]
    rows = _asset_inventory(events, dev_score={"box": 0})
    assert rows[0]["events"] == 0
    assert rows[0]["status"] == "CLEAN"


# ── get_inventory_overview: admin-only gate ─────────────────────

def test_inventory_overview_non_admin_returns_200_with_no_data(monkeypatch):
    monkeypatch.setattr(ravenhub, "_resolve_is_admin", lambda email: False)
    result = get_inventory_overview(email="dev@giggso.com")
    assert isinstance(result, InventoryOverviewResponse)
    assert result.is_admin is False
    assert result.message == "Not an admin — no inventory data available."
    assert result.ai_posture is None
    assert result.asset_inventory is None


def test_inventory_overview_unknown_email_returns_200_not_403(monkeypatch):
    def _deny(email):
        raise HTTPException(status_code=403, detail="Access denied")
    monkeypatch.setattr(ravenhub, "_resolve_is_admin", _deny)
    result = get_inventory_overview(email="totally-unknown@giggso.com")
    assert result.is_admin is False
    assert result.message == "Not an admin — no inventory data available."


def test_inventory_overview_admin_returns_full_data(monkeypatch):
    monkeypatch.setattr(ravenhub, "_resolve_is_admin", lambda email: True)
    monkeypatch.setattr(ravenhub, "_blob_store", lambda: object())
    fake_events = [_ev(src_hostname="box-1", category="browser", severity="HIGH")]
    monkeypatch.setattr(
        ravenhub, "_load_events",
        lambda store, email, is_admin: (fake_events, {}, {}, "2026-07-20"),
    )
    result = get_inventory_overview(email="admin@giggso.com")
    assert result.is_admin is True
    assert result.message is None
    assert result.source_date == "2026-07-20"
    assert result.ai_posture is not None
    assert result.ai_posture["score"] > 0
    assert result.asset_inventory[0]["asset_key"] == "box-1"


# ── _user_logs ───────────────────────────────────────────────────

def test_user_logs_sorted_newest_first_and_shaped():
    events = [
        _ev(timestamp="2026-07-20T05:00:00Z", provider="a.com", severity="LOW"),
        _ev(timestamp="2026-07-20T09:00:00Z", provider="b.com", severity="HIGH"),
    ]
    logs = _user_logs(events)
    assert [l["timestamp"] for l in logs] == ["2026-07-20T09:00:00Z", "2026-07-20T05:00:00Z"]
    assert logs[0]["provider"] == "b.com"
    assert logs[0]["severity"] == "HIGH"


def test_user_logs_caps_at_limit():
    events = [_ev(timestamp=f"2026-07-20T{h:02d}:00:00Z") for h in range(10)]
    logs = _user_logs(events, limit=5)
    assert len(logs) == 5


def test_user_logs_missing_provider_is_none_not_empty_string():
    events = [_ev(provider="")]
    logs = _user_logs(events)
    assert logs[0]["provider"] is None


# ── get_user_detail: admin-or-self access gate ──────────────────

def _stub_user_detail_deps(monkeypatch, events):
    """Stub out identity/S3/DB so get_user_detail runs fully offline."""
    monkeypatch.setattr(ravenhub, "_blob_store", lambda: object())
    monkeypatch.setattr(
        ravenhub, "_load_events",
        lambda store, email, is_admin: (events, {}, {}, "2026-07-20"),
    )
    monkeypatch.setattr(ravenhub, "_org_policy_context", lambda: None)
    monkeypatch.setattr(ravenhub, "_user_policy_context", lambda email, org_ctx: org_ctx)


def test_user_detail_admin_can_view_anyone(monkeypatch):
    monkeypatch.setattr(ravenhub, "_resolve_is_admin", lambda email: True)
    events = [_ev(email="target@giggso.com", severity="HIGH", provider="claude.ai")]
    _stub_user_detail_deps(monkeypatch, events)

    result = get_user_detail(viewer_email="admin@giggso.com", target_email="target@giggso.com")
    assert isinstance(result, UserDetailResponse)
    assert result.authorized is True
    assert result.message is None
    assert result.total_events == 1
    assert result.score["score"] >= 0
    assert result.logs[0]["provider"] == "claude.ai"


def test_user_detail_non_admin_can_view_self(monkeypatch):
    monkeypatch.setattr(ravenhub, "_resolve_is_admin", lambda email: False)
    events = [_ev(email="me@giggso.com")]
    _stub_user_detail_deps(monkeypatch, events)

    result = get_user_detail(viewer_email="me@giggso.com", target_email="me@giggso.com")
    assert result.authorized is True
    assert result.total_events == 1


def test_user_detail_non_admin_cannot_view_someone_else(monkeypatch):
    monkeypatch.setattr(ravenhub, "_resolve_is_admin", lambda email: False)

    result = get_user_detail(viewer_email="me@giggso.com", target_email="someone-else@giggso.com")
    assert result.authorized is False
    assert result.message == "Not authorized to view this user's data."
    assert result.score is None
    assert result.logs is None
    assert result.total_events is None


def test_user_detail_unresolvable_viewer_still_allows_self_view(monkeypatch):
    """An unrecognized viewer_email must not raise — it degrades to
    non-admin, and self-view (viewer == target) still works."""
    def _deny(email):
        raise HTTPException(status_code=403, detail="Access denied")
    monkeypatch.setattr(ravenhub, "_resolve_is_admin", _deny)
    events = [_ev(email="ghost@giggso.com")]
    _stub_user_detail_deps(monkeypatch, events)

    result = get_user_detail(viewer_email="ghost@giggso.com", target_email="ghost@giggso.com")
    assert result.authorized is True


def test_user_detail_unresolvable_viewer_denied_for_cross_view(monkeypatch):
    def _deny(email):
        raise HTTPException(status_code=403, detail="Access denied")
    monkeypatch.setattr(ravenhub, "_resolve_is_admin", _deny)

    result = get_user_detail(viewer_email="ghost@giggso.com", target_email="someone-else@giggso.com")
    assert result.authorized is False
