# =============================================================
# FILE: tests/unit/test_provider_views.py
# VERSION: 1.0.0
# UPDATED: 2026-06-29
# OWNER: Giggso Inc
# PURPOSE: All Providers / Newly Found computed views (Phase D). Pure.
# =============================================================

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from scoring.policy import PolicyContext
from scoring.provider_views import all_providers, newly_found


def _r(provider, sev="HIGH", cat="browser", occ=1, status="open", last_seen=""):
    return {"provider": provider, "severity": sev, "category": cat,
            "occurrences": occ, "status": status, "last_seen": last_seen}


def test_all_providers_dedups_and_aggregates():
    rows = [_r("claude.ai", occ=3), _r("claude.ai", sev="CRITICAL", occ=2),
            _r("copilot", cat="process")]
    out = all_providers(rows)
    by = {p["provider"]: p for p in out}
    assert set(by) == {"claude.ai", "copilot"}
    assert by["claude.ai"]["max_severity"] == "CRITICAL"
    assert by["claude.ai"]["occurrences"] == 5
    assert by["claude.ai"]["finding_count"] == 2


def test_all_providers_skips_resolved_and_blank():
    rows = [_r("x", status="resolved"), _r("")]
    assert all_providers(rows) == []


def test_all_providers_sorted_worst_first():
    rows = [_r("low1", sev="LOW"), _r("crit1", sev="CRITICAL")]
    out = all_providers(rows)
    assert out[0]["provider"] == "crit1"


def test_tier_and_multiplier_resolved_with_context():
    rows = [_r("claude.ai"), _r("evil.com"), _r("unknown.io")]
    ctx = PolicyContext(org_approve={"claude.ai"}, org_deny={"evil.com"})
    by = {p["provider"]: p for p in all_providers(rows, ctx)}
    assert by["claude.ai"]["tier"] == "org_approve"
    assert by["claude.ai"]["multiplier"] == 0.10
    assert by["evil.com"]["tier"] == "org_deny"
    assert by["unknown.io"]["tier"] == "unknown"


def test_newly_found_only_unknown_providers():
    rows = [_r("claude.ai"), _r("evil.com"), _r("mystery.ai")]
    ctx = PolicyContext(org_approve={"claude.ai"}, org_deny={"evil.com"})
    nf = {p["provider"] for p in newly_found(rows, ctx)}
    assert nf == {"mystery.ai"}


def test_newly_found_without_context_is_everything():
    rows = [_r("a"), _r("b")]
    assert {p["provider"] for p in newly_found(rows)} == {"a", "b"}
