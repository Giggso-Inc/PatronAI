# =============================================================
# FILE: src/scoring/risk_score.py
# VERSION: 2.0.0
# UPDATED: 2026-06-29
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: Weighted, POLICY-AWARE, VOLUME-FAIR risk score (0-100) for the
#          AI Posture card. Pure functions — no I/O — so unit-testable
#          without S3 / Streamlit / Polars.
#
# v2.0.0 (ADR_2026-06-29) replaces the v1 raw sum (which grew with data
# volume and saturated at 100) with a normalize + worst-case model:
#   • per-provider dedup + an optional policy multiplier (waterfall);
#   • worst-case is a FLOOR (a CRITICAL is never averaged away);
#   • breadth (count of other risky providers) adds on top but SATURATES,
#     so more findings/devices no longer linearly inflate the score.
# All weights live in scoring_weights.py (single editable home).
#
# AUDIT LOG:
#   v1.0.0  2026-05-11  Initial raw-sum model.
#   v2.0.0  2026-06-29  Policy waterfall + normalize/worst-case aggregation.
# =============================================================

from collections import defaultdict
from typing import Iterable, Optional

from scoring import scoring_weights as W
from scoring.policy import PolicyContext, policy_tier


def _base_weight(row: dict) -> float:
    """Severity × category × occurrence weight for one finding (pre-policy)."""
    if row.get("status") == "resolved":
        return 0.0
    sev = (row.get("severity") or "LOW").upper()
    cat = (row.get("category") or "").lower()
    base = W.SEVERITY_WEIGHT.get(sev, 1)
    mult = W.CATEGORY_MULTIPLIER.get(cat, 1.0)
    occ = int(row.get("occurrences") or 1)
    occ_factor = 1 + min(W.OCC_DAMP_MAX, W.OCC_DAMP_PER * (occ - 1))
    return base * mult * occ_factor


def _provider_key(row: dict, idx: int) -> str:
    """Stable grouping key — the provider, else a finding identifier, else
    the row index (keeps synthetic rows without a provider distinct)."""
    for k in ("provider", "finding_signature", "event_id"):
        v = (row.get(k) or "").strip().lower()
        if v:
            return v
    return f"__row_{idx}"


def risk_score(rows: Iterable[dict], policy_context: Optional[PolicyContext] = None) -> int:
    """Aggregate risk score 0-100 for a set of compacted finding rows.

    policy_context=None → policy-blind (every provider ×1.0), preserving
    backward-compatible call sites. Pass a resolved PolicyContext to apply
    the org/project/user allow & deny waterfall at scoring time.
    """
    # 1. Per-provider weight = max weighted finding for that provider
    #    (dedup so one tool spanning many categories isn't double-counted).
    per_provider: dict = defaultdict(float)
    has_override = False   # any provider on a guarded Giggso override (C2)
    for i, r in enumerate(rows):
        base = _base_weight(r)
        if base <= 0:
            continue
        provider = r.get("provider") or ""
        if policy_context is None:
            mult = 1.0
        else:
            tier = policy_tier(provider, policy_context)
            mult = W.POLICY_MULTIPLIER.get(tier, 1.0)   # unknown tier → neutral
            if "override" in tier:   # giggso OR deny override, any scope → band floor (C2/D2)
                has_override = True
        weighted = base * mult
        key = _provider_key(r, i)
        if weighted > per_provider[key]:
            per_provider[key] = weighted

    if not per_provider:
        return 0

    # 2. Worst-case is the floor — a CRITICAL provider can't be diluted.
    worst = max(per_provider.values())
    worst_floor = min(W.SCORE_CAP, worst)

    # 3. Breadth adds on top but saturates (volume-fairness): one extra
    #    risky tool matters, the 50th barely moves the needle.
    n_risky = sum(1 for v in per_provider.values() if v >= W.RISKY_MIN_WEIGHT)
    if worst >= W.RISKY_MIN_WEIGHT:
        n_risky -= 1                      # exclude the worst (already the floor)
    n_risky = max(0, n_risky)
    breadth = 1 - 1 / (1 + n_risky)       # 0 when alone; →1 saturating

    score = worst_floor + (W.SCORE_CAP - worst_floor) * breadth * W.BREADTH_GAIN
    score = int(min(W.SCORE_CAP, round(score)))

    # Condition C2: a permitted Giggso-baseline tool can't drag the device
    # below MEDIUM — never launder a baseline block to CLEAN/LOW.
    if has_override:
        score = max(score, W.OVERRIDE_BAND_FLOOR)
    return score


def risk_band(score: int) -> str:
    """Human label for a 0-100 score — drives card colour."""
    if score >= W.CRITICAL_AT: return "CRITICAL"
    if score >= W.HIGH_AT:     return "HIGH"
    if score >= W.MEDIUM_AT:   return "MEDIUM"
    if score > 0:              return "LOW"
    return "CLEAN"


def posture_breakdown(rows: Iterable[dict]) -> dict:
    """Group OPEN signatures by category for the posture card.
    Returns {category: {count, max_severity, last_seen}}."""
    out: dict = defaultdict(lambda: {"count": 0, "max_severity": "LOW",
                                     "last_seen": ""})
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    for r in rows:
        if r.get("status") == "resolved":
            continue
        cat = r.get("category") or "unknown"
        slot = out[cat]
        slot["count"] += 1
        sev = (r.get("severity") or "LOW").upper()
        if sev_rank.get(sev, 0) > sev_rank.get(slot["max_severity"], 0):
            slot["max_severity"] = sev
        ls = r.get("last_seen") or ""
        if ls > slot["last_seen"]:
            slot["last_seen"] = ls
    return dict(out)
