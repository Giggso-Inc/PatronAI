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

# ── Policy waterfall multipliers (ADR_2026-06-29) ────────────────────
# Applied PER PROVIDER. Deny beats approve; short-circuit on first match.
# giggso_override is the guarded, capped exception (Phase E) — an org
# explicitly permitting a Giggso-blocked tool lands at 0.5, NOT 0.1.
POLICY_MULTIPLIER = {
    "giggso_deny":     3.0,
    "org_deny":        2.0,
    "project_deny":       2.0,
    "user_deny":       2.0,
    "org_approve":     0.10,
    "project_approve":    0.15,
    "user_ack":        0.50,
    "giggso_override":         0.50,   # org-scope override (widest authority)
    "giggso_override_project": 0.60,   # project-scope override (narrower)
    "giggso_override_user":    0.70,   # user-scope override (narrowest / least reduction)
    # org/project-DENY override (security_log 2026-07-03, conditions D1-D7):
    # an org-admin permits, at a NARROWER scope, a tool a WIDER scope denied.
    # Capped like the giggso override and band-floored >= MEDIUM (D2). Narrower
    # grant = less reduction. The Giggso floor is never reached here (D4): a
    # giggso_deny is resolved before org/project deny in the waterfall.
    "deny_override_project":   0.60,   # permitted at a project despite an org deny
    "deny_override_user":      0.70,   # permitted at a user despite an org/project deny
    "unknown":         1.0,
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

# ── Security condition C2 (Phase E, security_log 2026-06-29) ─────────
# A device with an overridden Giggso-baseline provider can never read
# below this band — a baseline-blocked tool the org chose to permit must
# never be laundered to CLEAN/LOW.
OVERRIDE_BAND_FLOOR = MEDIUM_AT
