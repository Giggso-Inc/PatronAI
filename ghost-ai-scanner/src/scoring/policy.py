# =============================================================
# FILE: src/scoring/policy.py
# VERSION: 1.0.0
# UPDATED: 2026-06-29
# OWNER: Giggso Inc
# PURPOSE: Pure policy-waterfall logic (ADR_2026-06-29). Given a
#          provider string and a resolved PolicyContext, return the tier
#          and its score multiplier. No I/O — the context is built
#          elsewhere (policy_resolver) from CSV today / Postgres later.
#
# WATERFALL (deny beats approve; short-circuit on first match):
#   giggso_deny ×3.0  (→ ×0.5 if org explicitly overrode it)
#   org_deny / project_deny / user_deny ×2.0
#   org_approve ×0.1 / project_approve ×0.15 / user_ack ×0.5
#   unknown ×1.0
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
    Every set holds normalised (lowercase) provider glob patterns."""
    giggso_deny:     set = field(default_factory=set)
    org_deny:        set = field(default_factory=set)
    project_deny:       set = field(default_factory=set)
    user_deny:       set = field(default_factory=set)
    org_approve:     set = field(default_factory=set)
    project_approve:    set = field(default_factory=set)
    user_ack:        set = field(default_factory=set)
    # Providers an org admin explicitly overrode despite a Giggso block,
    # bucketed by the scope the override was granted at (org/project/user).
    giggso_override:         set = field(default_factory=set)   # org scope
    giggso_override_project: set = field(default_factory=set)
    giggso_override_user:    set = field(default_factory=set)

    @classmethod
    def empty(cls) -> "PolicyContext":
        return cls()


def policy_tier(provider: str, ctx: PolicyContext) -> str:
    """Return the winning waterfall tier name for a provider."""
    # 1. Giggso baseline deny — unless explicitly overridden. Most-specific
    #    scope wins (user > project > org); each has its own capped weight.
    if _matches(provider, ctx.giggso_deny):
        if _matches(provider, ctx.giggso_override_user):
            return "giggso_override_user"
        if _matches(provider, ctx.giggso_override_project):
            return "giggso_override_project"
        if _matches(provider, ctx.giggso_override):
            return "giggso_override"
        return "giggso_deny"
    # 2-4. Org / project / user deny (deny always beats approve).
    if _matches(provider, ctx.org_deny):
        return "org_deny"
    if _matches(provider, ctx.project_deny):
        return "project_deny"
    if _matches(provider, ctx.user_deny):
        return "user_deny"
    # 5-7. Approvals, most-authoritative scope first.
    if _matches(provider, ctx.org_approve):
        return "org_approve"
    if _matches(provider, ctx.project_approve):
        return "project_approve"
    if _matches(provider, ctx.user_ack):
        return "user_ack"
    return "unknown"


def policy_multiplier(provider: str, ctx) -> float:
    """Score multiplier for a provider. ctx=None → 1.0 (policy-blind /
    backward-compatible path used before any context is resolved)."""
    if ctx is None:
        return 1.0
    # .get(...) default: if a new tier is ever added to policy_tier() without a
    # matching weights entry, fail neutral (1.0) rather than raise KeyError.
    return POLICY_MULTIPLIER.get(policy_tier(provider, ctx), 1.0)
