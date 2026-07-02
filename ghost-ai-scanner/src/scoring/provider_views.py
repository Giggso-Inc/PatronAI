# =============================================================
# FILE: src/scoring/provider_views.py
# VERSION: 1.0.0
# UPDATED: 2026-06-29
# OWNER: Giggso Inc
# PURPOSE: Pure computed views for the Provider Governance tab
#          (Phase D, ADR_2026-06-29):
#            • all_providers — every distinct provider seen + its resolved
#              waterfall tier/multiplier (the master table).
#            • newly_found  — providers resolving to 'unknown' (in no list
#              at any scope) → the admin Allow/Block queue.
#          Pure (no DB/Streamlit) so both are fully unit-testable. The UI
#          layer just renders these + wires the one-click actions.
# =============================================================

from collections import defaultdict

from scoring.policy import PolicyContext, policy_tier
from scoring.scoring_weights import POLICY_MULTIPLIER

_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def all_providers(rows, policy_context: PolicyContext = None) -> list:
    """One row per distinct provider seen, with its resolved policy tier.

    Returns dicts sorted worst-first:
      {provider, category, max_severity, occurrences, last_seen, finding_count,
       tier, multiplier}
    'tier' is 'unknown' when no policy context is supplied."""
    agg: dict = {}
    for r in rows:
        if r.get("status") == "resolved":
            continue
        p = (r.get("provider") or "").strip()
        if not p:
            continue
        slot = agg.get(p)
        if slot is None:
            slot = agg[p] = {
                "provider": p, "category": r.get("category") or "",
                "max_severity": "LOW", "occurrences": 0,
                "last_seen": "", "finding_count": 0,
            }
        sev = (r.get("severity") or "LOW").upper()
        if _SEV_RANK.get(sev, 0) > _SEV_RANK.get(slot["max_severity"], 0):
            slot["max_severity"] = sev
            slot["category"] = r.get("category") or slot["category"]
        slot["occurrences"] += int(r.get("occurrences") or 1)
        slot["finding_count"] += 1
        ls = r.get("last_seen") or ""
        if ls > slot["last_seen"]:
            slot["last_seen"] = ls

    out = []
    for slot in agg.values():
        tier = policy_tier(slot["provider"], policy_context) if policy_context else "unknown"
        slot["tier"] = tier
        slot["multiplier"] = POLICY_MULTIPLIER[tier] if policy_context else 1.0
        out.append(slot)

    out.sort(key=lambda s: (-_SEV_RANK.get(s["max_severity"], 0), -s["finding_count"]))
    return out


def newly_found(rows, policy_context: PolicyContext = None) -> list:
    """Providers resolving to 'unknown' — not on any allow/deny list at any
    scope. These are the admin's Allow/Block review queue."""
    return [p for p in all_providers(rows, policy_context) if p["tier"] == "unknown"]
