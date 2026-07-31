# =============================================================
# FILE: src/scoring/policy.py
# VERSION: 2.0.0
# UPDATED: 2026-07-31
# OWNER: Giggso Inc
# PURPOSE: Pure policy-waterfall logic. Given a provider string and a
#          resolved PolicyContext, return the tier and its score
#          multiplier. No I/O — the context is built elsewhere
#          (policy_resolver / policy_queries).
#
# WATERFALL (ADR_2026-07-31 — scope-first, "most-specific-wins"):
#   user rule (allow OR deny)    wins outright, whichever polarity it is
#   project rule (allow OR deny) wins if no user-scope rule exists
#   org rule (allow OR deny)     wins if no project/user-scope rule exists
#   unknown ×1.0-equivalent      → treated as deny-weight (see
#                                  scoring_weights.DENY_MULTIPLIER) but kept
#                                  as a DISTINCT tier name ("unknown") so the
#                                  UI can show it as unclassified, not denied.
#
# A pattern can never hold both an allow and a deny row at the SAME scope
# (OQ-4) — enforced at the write path (db.governance_crud) and by a DB
# trigger, so no same-scope tie-break is needed here.
# =============================================================

import fnmatch
from dataclasses import dataclass, field

from scoring.scoring_weights import POLICY_MULTIPLIER


def _norm(s) -> str:
    """Normalise a provider/domain to trimmed lowercase.

    Tolerates non-str input: pandas reads a blank CSV cell as float('nan'),
    which is TRUTHY — so the old `(s or "")` let a NaN through to `.strip()`
    and blew up with "'float' object has no attribute 'strip'". Coerce to str
    and treat NaN/None as empty."""
    if s is None:
        return ""
    text = str(s).strip().lower()
    return "" if text == "nan" else text


def _matches(provider: str, patterns: set) -> bool:
    """Exact or glob (fnmatch) match of a provider against a pattern set."""
    p = _norm(provider)
    if not p or not patterns:
        return False
    if p in patterns:
        return True
    return any(fnmatch.fnmatch(p, pat) for pat in patterns if "*" in pat or "?" in pat)


@dataclass
class PolicyContext:
    """Resolved allow/deny pattern sets for ONE user, across scopes.
    Every set holds normalised (lowercase) provider glob patterns.

    No `giggso_*` / `*_override` / `deny_override_*` fields — removed by
    ADR_2026-07-31 along with the Giggso baseline tier and the guarded-
    override machinery that existed only to protect it."""
    org_deny:        set = field(default_factory=set)
    project_deny:    set = field(default_factory=set)
    user_deny:       set = field(default_factory=set)
    org_approve:     set = field(default_factory=set)
    project_approve: set = field(default_factory=set)
    user_ack:        set = field(default_factory=set)

    @classmethod
    def empty(cls) -> "PolicyContext":
        return cls()


def policy_tier(provider: str, ctx: PolicyContext) -> str:
    """Return the winning waterfall tier name for a provider.

    Scope-first ("most-specific-wins", ADR_2026-07-31): a user-scope rule —
    allow OR deny — always wins outright over project, which always wins
    over org. Polarity (allow vs deny) only decides which of the two rules
    AT THE SAME SCOPE applies, and OQ-4 guarantees a scope can never hold
    both for the same pattern, so no tie-break is needed."""
    if _matches(provider, ctx.user_deny):
        return "user_deny"
    if _matches(provider, ctx.user_ack):
        return "user_ack"
    if _matches(provider, ctx.project_deny):
        return "project_deny"
    if _matches(provider, ctx.project_approve):
        return "project_approve"
    if _matches(provider, ctx.org_deny):
        return "org_deny"
    if _matches(provider, ctx.org_approve):
        return "org_approve"
    return "unknown"


def policy_multiplier(provider: str, ctx) -> float:
    """Score multiplier for a provider. ctx=None → 1.0 (policy-blind /
    backward-compatible path used before any context is resolved)."""
    if ctx is None:
        return 1.0
    # .get(...) default: if a new tier is ever added to policy_tier() without a
    # matching weights entry, fail neutral (1.0) rather than raise KeyError.
    return POLICY_MULTIPLIER.get(policy_tier(provider, ctx), 1.0)
