# =============================================================
# FILE: tests/unit/test_policy.py
# VERSION: 1.0.0
# UPDATED: 2026-06-29
# OWNER: Giggso Inc
# PURPOSE: Lock the policy waterfall (ADR_2026-06-29) — tier resolution
#          and multipliers. Pure; no DB.
# =============================================================

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import scoring.policy as _pol
from scoring.policy import PolicyContext, policy_tier, policy_multiplier, _norm
from scoring.scoring_weights import POLICY_MULTIPLIER


def test_unknown_provider_is_neutral():
    assert policy_tier("anything", PolicyContext.empty()) == "unknown"
    assert policy_multiplier("anything", PolicyContext.empty()) == 1.0


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


def test_full_waterfall_order_and_multipliers():
    cases = [
        ("giggso_deny",  PolicyContext(giggso_deny={"x"}),  3.0),
        ("org_deny",     PolicyContext(org_deny={"x"}),     2.0),
        ("project_deny",    PolicyContext(project_deny={"x"}),    2.0),
        ("user_deny",    PolicyContext(user_deny={"x"}),    2.0),
        ("org_approve",  PolicyContext(org_approve={"x"}),  0.10),
        ("project_approve", PolicyContext(project_approve={"x"}), 0.15),
        ("user_ack",     PolicyContext(user_ack={"x"}),     0.50),
    ]
    for tier, ctx, mult in cases:
        assert policy_tier("x", ctx) == tier
        assert policy_multiplier("x", ctx) == mult == POLICY_MULTIPLIER[tier]


def test_deny_beats_approve_at_every_scope():
    ctx = PolicyContext(org_approve={"x"}, org_deny={"x"})
    assert policy_tier("x", ctx) == "org_deny"


def test_giggso_deny_wins_over_org_approve():
    ctx = PolicyContext(giggso_deny={"x"}, org_approve={"x"})
    assert policy_tier("x", ctx) == "giggso_deny"


def test_giggso_override_flips_baseline_to_capped():
    ctx = PolicyContext(giggso_deny={"x"}, giggso_override={"x"})
    assert policy_tier("x", ctx) == "giggso_override"
    assert policy_multiplier("x", ctx) == 0.50


def test_override_only_applies_when_also_baseline_denied():
    # override set without a baseline deny has no effect (not a free approve)
    ctx = PolicyContext(giggso_override={"x"})
    assert policy_tier("x", ctx) == "unknown"


def test_glob_and_case_insensitive_match():
    ctx = PolicyContext(org_approve={"mcp:claude_desktop:*"})
    assert policy_tier("MCP:Claude_Desktop:puppeteer", ctx) == "org_approve"


def test_scoped_giggso_override_tiers_and_weights():
    cases = [
        ("giggso_override",         "giggso_override",         0.50),
        ("giggso_override_project", "giggso_override_project", 0.60),
        ("giggso_override_user",    "giggso_override_user",    0.70),
    ]
    for field_name, tier, mult in cases:
        ctx = PolicyContext(giggso_deny={"x"}, **{field_name: {"x"}})
        assert policy_tier("x", ctx) == tier
        assert policy_multiplier("x", ctx) == mult == POLICY_MULTIPLIER[tier]


def test_override_precedence_user_over_project_over_org():
    ctx = PolicyContext(giggso_deny={"x"}, giggso_override={"x"},
                        giggso_override_project={"x"}, giggso_override_user={"x"})
    assert policy_tier("x", ctx) == "giggso_override_user"   # most specific wins


# ── deny-override (allow what a WIDER scope blocked) — 2026-07-03 D1-D7 ──

def test_deny_override_of_org_deny_tiers_and_weights():
    # org-denied tool permitted at project → deny_override_project (×0.60)
    ctx = PolicyContext(org_deny={"x"}, deny_override_project={"x"})
    assert policy_tier("x", ctx) == "deny_override_project"
    assert policy_multiplier("x", ctx) == 0.60
    # a user-scope grant is more specific → wins, ×0.70
    ctx2 = PolicyContext(org_deny={"x"}, deny_override_project={"x"},
                         deny_override_user={"x"})
    assert policy_tier("x", ctx2) == "deny_override_user"
    assert policy_multiplier("x", ctx2) == 0.70


def test_deny_override_of_project_deny_only_at_user():
    ctx = PolicyContext(project_deny={"x"}, deny_override_user={"x"})
    assert policy_tier("x", ctx) == "deny_override_user"
    # a project-scope grant does NOT override a project deny (same scope)
    ctx2 = PolicyContext(project_deny={"x"}, deny_override_project={"x"})
    assert policy_tier("x", ctx2) == "project_deny"


def test_deny_override_never_touches_giggso_floor_d4():
    # D4: a Giggso-blocked tool resolves first; a deny-override can't lower it.
    ctx = PolicyContext(giggso_deny={"x"}, org_deny={"x"}, deny_override_user={"x"})
    assert policy_tier("x", ctx) == "giggso_deny"
    assert policy_multiplier("x", ctx) == 3.0
