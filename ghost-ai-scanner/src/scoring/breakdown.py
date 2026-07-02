# =============================================================
# FILE: src/scoring/breakdown.py
# VERSION: 1.0.0
# UPDATED: 2026-06-30
# OWNER: Giggso Inc
# PURPOSE: Explainability for the risk score — decompose a score into its
#          per-provider contributions, and aggregate per-unit (device/user)
#          scores into a fleet number. Pure (no I/O), fully unit-testable.
#          Used by the AI Posture card breakdown, the Asset Inventory score
#          column, and the User-detail page.
#          score_detail()['score'] is ALWAYS == risk_score() (delegates),
#          so the breakdown can never disagree with the headline.
# =============================================================

from scoring import scoring_weights as W
from scoring.policy import policy_tier
from scoring.risk_score import _base_weight, _provider_key, risk_band, risk_score


def provider_contributions(rows, policy_context=None) -> list:
    """One row per distinct provider with its scoring contribution:
    {provider, category, severity, occurrences, tier, multiplier, base, weighted}.
    Deduped per provider (max-weighted finding), sorted worst-first."""
    agg: dict = {}
    for i, r in enumerate(rows):
        base = _base_weight(r)
        if base <= 0:
            continue
        provider = r.get("provider") or ""
        if policy_context is None:
            tier, mult = "unknown", 1.0
        else:
            tier = policy_tier(provider, policy_context)
            mult = W.POLICY_MULTIPLIER[tier]
        weighted = base * mult
        key = _provider_key(r, i)
        cur = agg.get(key)
        if cur is None or weighted > cur["weighted"]:
            agg[key] = {
                "provider": provider or key,
                "category": r.get("category") or "",
                "severity": (r.get("severity") or "LOW").upper(),
                "occurrences": int(r.get("occurrences") or 1),
                "tier": tier, "multiplier": mult,
                "base": round(base, 1), "weighted": round(weighted, 1),
            }
    return sorted(agg.values(), key=lambda d: -d["weighted"])


def score_detail(rows, policy_context=None) -> dict:
    """Full breakdown for one unit (device/user/fleet):
    {score, band, worst, risky_count, providers:[...]}.
    `score` delegates to risk_score so it always matches the headline."""
    provs = provider_contributions(rows, policy_context)
    score = risk_score(rows, policy_context)
    weights = [p["weighted"] for p in provs]
    worst = min(W.SCORE_CAP, max(weights)) if weights else 0
    return {
        "score": score, "band": risk_band(score),
        "worst": round(worst, 1),
        "risky_count": sum(1 for w in weights if w >= W.RISKY_MIN_WEIGHT),
        "providers": provs,
    }


# Fleet aggregation weights (owner decision 2026-06-30): worst-case blend,
# so one bad device can't be averaged away by clean ones.
FLEET_WORST_WEIGHT = 0.6
FLEET_AVG_WEIGHT = 0.4


def fleet_blend(scores) -> int:
    """Aggregate per-device scores: 60% worst device + 40% average."""
    s = [x for x in scores if x is not None]
    if not s:
        return 0
    return int(round(FLEET_WORST_WEIGHT * max(s) + FLEET_AVG_WEIGHT * (sum(s) / len(s))))
