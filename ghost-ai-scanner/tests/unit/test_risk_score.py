# =============================================================
# FILE: tests/unit/test_risk_score.py
# VERSION: 1.0.0
# UPDATED: 2026-05-11
# OWNER: Giggso Inc
# PURPOSE: Lock the risk scoring contract — drives the AI Posture
#          card. If these numbers drift, the headline UX drifts.
# =============================================================

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "src"))

from scoring.risk_score import (
    risk_score, risk_band, posture_breakdown,
)
from scoring.policy import PolicyContext


def _row(sev="HIGH", cat="process", occ=1, status="open"):
    return {"severity": sev, "category": cat, "occurrences": occ,
            "status": status}


def _prow(provider, sev="CRITICAL", cat="process", occ=1):
    return {"provider": provider, "severity": sev, "category": cat,
            "occurrences": occ, "status": "open"}


def test_empty_input_is_clean():
    assert risk_score([]) == 0
    assert risk_band(0) == "CLEAN"


def test_resolved_rows_do_not_score():
    rows = [_row(sev="CRITICAL", status="resolved")]
    assert risk_score(rows) == 0


def test_single_high_process_contributes():
    s = risk_score([_row(sev="HIGH", cat="process")])
    assert s > 0
    assert s < 75  # one HIGH shouldn't pin red


def test_one_critical_drives_red():
    """A single CRITICAL finding alone must push the device to CRITICAL band."""
    s = risk_score([_row(sev="CRITICAL", cat="process")])
    assert risk_band(s) == "CRITICAL", f"score={s} expected CRITICAL band"


def test_score_never_exceeds_100():
    # 50 distinct critical providers: breadth saturates, never overflows.
    rows = [dict(_row(sev="CRITICAL", cat="process"), provider=f"tool{i}")
            for i in range(50)]
    s = risk_score(rows)
    assert s <= 100
    assert risk_band(s) == "CRITICAL"


def test_category_multiplier_applied():
    """A running process scores higher than a stale shell-history line."""
    proc = risk_score([_row(sev="HIGH", cat="process")])
    hist = risk_score([_row(sev="HIGH", cat="shell_history")])
    assert proc > hist


def test_occurrences_dampened():
    """Seen 100 times is worse than seen once but not 100×."""
    once = risk_score([_row(sev="HIGH", cat="process", occ=1)])
    many = risk_score([_row(sev="HIGH", cat="process", occ=100)])
    assert many > once
    assert many < once * 10


def test_band_thresholds():
    assert risk_band(0)   == "CLEAN"
    assert risk_band(5)   == "LOW"
    assert risk_band(20)  == "MEDIUM"
    assert risk_band(50)  == "HIGH"
    assert risk_band(80)  == "CRITICAL"
    assert risk_band(100) == "CRITICAL"


# ── posture_breakdown ──────────────────────────────────────────

def test_posture_breakdown_groups_by_category():
    rows = [
        _row(cat="process", sev="HIGH"),
        _row(cat="process", sev="CRITICAL"),
        _row(cat="vector_db", sev="MEDIUM"),
    ]
    b = posture_breakdown(rows)
    assert b["process"]["count"] == 2
    assert b["process"]["max_severity"] == "CRITICAL"
    assert b["vector_db"]["count"] == 1


def test_posture_breakdown_skips_resolved():
    rows = [
        _row(cat="process", status="open"),
        _row(cat="process", status="resolved"),
    ]
    b = posture_breakdown(rows)
    assert b["process"]["count"] == 1


def test_posture_breakdown_picks_latest_last_seen():
    rows = [
        {"category": "process", "severity": "HIGH",
         "occurrences": 1, "last_seen": "2026-05-10T00:00:00"},
        {"category": "process", "severity": "HIGH",
         "occurrences": 1, "last_seen": "2026-05-11T12:00:00"},
    ]
    b = posture_breakdown(rows)
    assert b["process"]["last_seen"] == "2026-05-11T12:00:00"


# ── v2: volume-fairness (the core fix) ─────────────────────────

def test_same_provider_repeats_do_not_inflate():
    """One critical tool vs the SAME tool seen 50× → identical score
    (dedup per provider). This is the headline bug being fixed."""
    one  = risk_score([_prow("copilot")])
    many = risk_score([_prow("copilot") for _ in range(50)])
    assert one == many


def test_low_severity_noise_does_not_average_away_a_critical():
    """A CRITICAL stays CRITICAL even buried under many LOW findings
    (worst-case is a floor, not an average)."""
    rows = [_prow("evil-llm")] + [
        _prow(f"noise{i}", sev="LOW", cat="shell_history") for i in range(40)
    ]
    assert risk_band(risk_score(rows)) == "CRITICAL"


def test_distinct_risky_providers_increase_but_saturate():
    """More distinct risky tools nudge the score up, with diminishing
    returns — never the old linear blow-up."""
    base = risk_score([_prow("a", sev="HIGH")])
    few  = risk_score([_prow(c, sev="HIGH") for c in "abc"])
    many = risk_score([_prow(f"t{i}", sev="HIGH") for i in range(40)])
    assert few > base
    assert many >= few
    assert many <= 100


# ── v2: policy waterfall applied at scoring time ───────────────

def test_org_approved_tool_is_downweighted():
    """An org-approved critical tool drops far below an unapproved one."""
    rows = [_prow("copilot")]
    unapproved = risk_score(rows)
    approved = risk_score(rows, PolicyContext(org_approve={"copilot"}))
    assert approved < unapproved
    assert risk_band(approved) in ("CLEAN", "LOW")


def test_org_denied_tool_is_upweighted():
    """A denied provider scores higher than the same finding unflagged."""
    rows = [_prow("sketchy.ai", sev="HIGH", cat="browser")]
    plain = risk_score(rows)
    denied = risk_score(rows, PolicyContext(org_deny={"sketchy.ai"}))
    assert denied > plain


def test_deny_beats_approve_at_the_same_scope():
    """If a provider is both approved and denied AT THE SAME SCOPE, deny
    wins the tie (OQ-4 makes this state unreachable via the real write
    path — governance_crud rejects it — but policy_tier() itself still
    must resolve deterministically if ever constructed directly)."""
    rows = [_prow("conflict.ai", sev="HIGH", cat="browser")]
    ctx = PolicyContext(org_approve={"conflict.ai"}, org_deny={"conflict.ai"})
    s_both = risk_score(rows, ctx)
    s_approve = risk_score(rows, PolicyContext(org_approve={"conflict.ai"}))
    assert s_both > s_approve  # deny multiplier applied, not approve


def test_user_allow_beats_org_deny_scope_first():
    """ADR_2026-07-31: scope-first precedence — a user-scope allow now wins
    outright over an org-scope deny (the opposite of the old
    polarity-first waterfall, which this replaces)."""
    rows = [_prow("ollama", sev="HIGH", cat="process")]
    org_denied = risk_score(rows, PolicyContext(org_deny={"ollama"}))
    user_allowed = risk_score(
        rows, PolicyContext(org_deny={"ollama"}, user_ack={"ollama"})
    )
    assert user_allowed < org_denied
    assert risk_band(user_allowed) in ("CLEAN", "LOW")


def test_glob_pattern_match_in_policy():
    """Provider patterns support globs (mcp:claude_desktop:* etc.)."""
    rows = [_prow("mcp:claude_desktop:puppeteer", sev="HIGH", cat="mcp_server")]
    ctx = PolicyContext(org_approve={"mcp:claude_desktop:*"})
    assert risk_score(rows, ctx) < risk_score(rows)
