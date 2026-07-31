# =============================================================
# FILE: tests/unit/test_policy.py
# VERSION: 2.0.0
# UPDATED: 2026-07-31
# OWNER: Giggso Inc
# PURPOSE: Lock the policy waterfall (ADR_2026-07-31) — scope-first
#          ("most-specific-wins") tier resolution and the 2-constant
#          multiplier model. Pure; no DB.
# AUDIT LOG:
#   v1.0.0  2026-06-29  Polarity-first waterfall (superseded).
#   v2.0.0  2026-07-31  Rewritten for scope-first precedence; dropped all
#                       giggso_*/deny_override_* cases (tiers removed).
# =============================================================

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import scoring.policy as _pol
from scoring.policy import PolicyContext, policy_tier, policy_multiplier, _norm
from scoring.scoring_weights import POLICY_MULTIPLIER, DENY_MULTIPLIER, APPROVE_MULTIPLIER


def test_unknown_provider_defaults_to_deny_weight():
    """ADR_2026-07-31: no rule anywhere -> distinct 'unknown' tier, but it
    scores at deny-weight (default-to-blocked-until-reviewed), not neutral."""
    assert policy_tier("anything", PolicyContext.empty()) == "unknown"
    assert policy_multiplier("anything", PolicyContext.empty()) == DENY_MULTIPLIER


def test_norm_tolerates_non_string_input():
    """PR#8: blank CSV cells arrive as float NaN — _norm must not crash."""
    assert _norm(float("nan")) == ""
    assert _norm(None) == ""
    assert _norm("  AbC.com ") == "abc.com"
    assert _norm(123) == "123"


def test_policy_multiplier_defaults_neutral_for_unknown_tier(monkeypatch):
    """PR#8: a tier with no weights entry fails neutral (1.0), not KeyError."""
    monkeypatch.setattr(_pol, "policy_tier", lambda provider, ctx: "brand_new_tier")
    assert _pol.policy_multiplier("x", PolicyContext()) == 1.0


def test_none_context_is_policy_blind():
    assert policy_multiplier("anything", None) == 1.0


def test_full_waterfall_tiers_and_multipliers():
    cases = [
        ("org_deny",        PolicyContext(org_deny={"x"}),        DENY_MULTIPLIER),
        ("project_deny",    PolicyContext(project_deny={"x"}),    DENY_MULTIPLIER),
        ("user_deny",       PolicyContext(user_deny={"x"}),       DENY_MULTIPLIER),
        ("org_approve",     PolicyContext(org_approve={"x"}),     APPROVE_MULTIPLIER),
        ("project_approve", PolicyContext(project_approve={"x"}), APPROVE_MULTIPLIER),
        ("user_ack",        PolicyContext(user_ack={"x"}),        APPROVE_MULTIPLIER),
    ]
    for tier, ctx, mult in cases:
        assert policy_tier("x", ctx) == tier
        assert policy_multiplier("x", ctx) == mult == POLICY_MULTIPLIER[tier]


def test_user_rule_beats_project_and_org_regardless_of_polarity():
    """ADR_2026-07-31: scope-first — a user-scope rule wins outright, even
    when it's an ALLOW against a wider DENY (the opposite of the old
    polarity-first waterfall)."""
    ctx = PolicyContext(org_deny={"x"}, project_deny={"x"}, user_ack={"x"})
    assert policy_tier("x", ctx) == "user_ack"
    assert policy_multiplier("x", ctx) == APPROVE_MULTIPLIER


def test_user_deny_beats_org_approve():
    ctx = PolicyContext(org_approve={"x"}, user_deny={"x"})
    assert policy_tier("x", ctx) == "user_deny"


def test_project_rule_beats_org_when_no_user_rule():
    ctx = PolicyContext(org_deny={"x"}, project_approve={"x"})
    assert policy_tier("x", ctx) == "project_approve"


def test_org_rule_applies_only_when_nothing_narrower_exists():
    ctx = PolicyContext(org_deny={"x"})
    assert policy_tier("x", ctx) == "org_deny"


def test_glob_and_case_insensitive_match():
    ctx = PolicyContext(org_approve={"mcp:claude_desktop:*"})
    assert policy_tier("MCP:Claude_Desktop:puppeteer", ctx) == "org_approve"
