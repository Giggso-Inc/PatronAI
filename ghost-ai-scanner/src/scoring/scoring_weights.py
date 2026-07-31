# =============================================================
# FILE: src/scoring/scoring_weights.py
# VERSION: 1.0.0
# UPDATED: 2026-06-29
# OWNER: Giggso Inc
# PURPOSE: SINGLE editable home for every risk-scoring weight
#          (owner requirement 2026-06-29). Adjust a number here and the
#          whole AI-Posture score shifts — no logic hunting required.
#          Pure data: no imports, no I/O.
#
# TUNING NOTE (B0): the aggregation constants below were chosen to keep
# the historical invariant "one CRITICAL process → CRITICAL band" while
# making the score volume-fair. Re-tune against the real temp/Database
# sample before release; that is expected, not a regression.
# =============================================================

# ── Severity weights — contribution of ONE finding at each severity ──
# 50×1.5 (process) = 75 → exactly the CRITICAL band floor, so a single
# critical running tool alone reads CRITICAL. Tune with care.
SEVERITY_WEIGHT = {
    "CRITICAL": 50,
    "HIGH":     12,
    "MEDIUM":    4,
    "LOW":       1,
}

# ── Category multipliers — a live process is more urgent than a stale
# shell-history line at the same severity. Applied after severity. ──
CATEGORY_MULTIPLIER = {
    "process":              1.5,
    "mcp_server":           1.4,
    "agent_workflow":       1.3,
    "agent_scheduled":      1.3,
    "browser":              1.1,
    "container_log_signal": 1.2,
    "vector_db":            1.0,
    "package":              0.9,
    "ide_plugin":           0.9,
    "container_image":      0.8,
    "tool_registration":    0.7,
    "shell_history":        0.5,
}

# ── Occurrence dampening — seen 100× is worse than once, not 100× worse.
# factor = 1 + min(OCC_DAMP_MAX, OCC_DAMP_PER * (occ - 1))
OCC_DAMP_PER = 0.05
OCC_DAMP_MAX = 0.5

# ── Policy waterfall multipliers (ADR_2026-07-31) ────────────────────
# Scope no longer changes HOW MUCH a rule is trusted — only WHICH rule wins
# (policy.policy_tier() is scope-first: user > project > org). So there is
# exactly one multiplier per polarity, not one per scope. Values kept at the
# prior org-scope numbers (least risky choice — a known-tuned pair); tune
# here if real data suggests otherwise.
DENY_MULTIPLIER = 2.0      # any winning deny rule, at any scope
APPROVE_MULTIPLIER = 0.10  # any winning approve rule, at any scope
# unknown = no rule at ANY scope. Scores at deny-weight by design (default to
# blocked until reviewed) but keeps a DISTINCT tier name from org_deny/etc so
# the UI can render it as "unclassified", never as an explicit denial.
POLICY_MULTIPLIER = {
    "org_deny":        DENY_MULTIPLIER,
    "project_deny":    DENY_MULTIPLIER,
    "user_deny":       DENY_MULTIPLIER,
    "org_approve":     APPROVE_MULTIPLIER,
    "project_approve": APPROVE_MULTIPLIER,
    "user_ack":        APPROVE_MULTIPLIER,
    "unknown":         DENY_MULTIPLIER,
}

# ── Aggregation (normalize + worst-case) — replaces the old raw sum ──
# score = worst_floor + (CAP - worst_floor) * breadth * BREADTH_GAIN
#   worst_floor = the single highest per-provider weight (worst-case
#                 preserved — a CRITICAL can never be averaged away).
#   breadth     = 1 - 1/(1 + n_other_risky_providers)  (saturating, so
#                 more distinct risky tools nudge UP but never linearly —
#                 this is the volume-fairness fix).
SCORE_CAP = 100
RISKY_MIN_WEIGHT = 4.0   # a provider with weight ≥ this counts as "risky" (≈ MEDIUM)
BREADTH_GAIN = 0.5       # how much breadth can add on top of the worst-case floor

# ── Band thresholds — drive the card colour/label ────────────────────
CRITICAL_AT = 75
HIGH_AT     = 40
MEDIUM_AT   = 15
