# =============================================================
# FILE: tests/unit/test_breakdown.py
# VERSION: 1.0.0
# UPDATED: 2026-06-30
# OWNER: Giggso Inc
# PURPOSE: Score breakdown + fleet blend (explainability). Pure.
# =============================================================

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from scoring.breakdown import fleet_blend, provider_contributions, score_detail
from scoring.policy import PolicyContext
from scoring.risk_score import risk_score


def _r(provider, sev="HIGH", cat="browser", occ=1):
    return {"provider": provider, "severity": sev, "category": cat,
            "occurrences": occ, "status": "open"}


def test_score_detail_matches_risk_score():
    rows = [_r("claude.ai", sev="CRITICAL", cat="process"), _r("copilot")]
    ctx = PolicyContext(org_approve={"copilot"})
    assert score_detail(rows, ctx)["score"] == risk_score(rows, ctx)
    assert score_detail(rows)["score"] == risk_score(rows)


def test_provider_contributions_carry_tier_and_multiplier():
    rows = [_r("claude.ai"), _r("evil.com")]
    ctx = PolicyContext(org_approve={"claude.ai"}, org_deny={"evil.com"})
    by = {p["provider"]: p for p in provider_contributions(rows, ctx)}
    assert by["claude.ai"]["tier"] == "org_approve" and by["claude.ai"]["multiplier"] == 0.10
    assert by["evil.com"]["tier"] == "org_deny" and by["evil.com"]["multiplier"] == 2.0
    # approved tool weighs less than denied — sorted worst-first
    assert provider_contributions(rows, ctx)[0]["provider"] == "evil.com"


def test_provider_contributions_dedup_per_provider():
    rows = [_r("claude.ai", occ=1), _r("claude.ai", sev="CRITICAL", occ=2)]
    pc = provider_contributions(rows)
    assert len(pc) == 1 and pc[0]["severity"] == "CRITICAL"


def test_fleet_blend_worst_case_weighted():
    # 0.6*max + 0.4*avg  ->  0.6*100 + 0.4*20 = 68 (not ~20 like a pure average)
    assert fleet_blend([100, 0, 0, 0, 0]) == 68     # one critical device can't be diluted
    assert fleet_blend([50]) == 50
    assert fleet_blend([]) == 0
    assert fleet_blend([80, 40]) == int(round(0.6 * 80 + 0.4 * 60))  # 48+24=72


def test_fleet_blend_ignores_none():
    assert fleet_blend([50, None, 50]) == 50
