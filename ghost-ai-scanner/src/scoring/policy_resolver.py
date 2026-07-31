# =============================================================
# FILE: src/scoring/policy_resolver.py
# VERSION: 2.0.0
# UPDATED: 2026-07-31
# OWNER: Giggso Inc
# PURPOSE: Build a PolicyContext from already-loaded list rows (PURE —
#          callers do the S3/DB I/O). CSV-mode (no DATABASE_URL) org-scope
#          context; the DB-backed builder (policy_queries.load_policy_context)
#          fills project/user scopes for the same PolicyContext shape.
# AUDIT LOG:
#   v1.0.0  2026-06-29  Initial (Phase A).
#   v2.0.0  2026-07-31  ADR_2026-07-31: no more separate `giggso_deny` —
#                       the Giggso-authored baseline rows fold into
#                       `org_deny` like any other org-scope deny content.
# =============================================================

from collections.abc import Iterable

from scoring.policy import PolicyContext, _norm


def _patterns(rows: Iterable[dict], *cols: str) -> set:
    """Collect normalised, non-comment provider patterns from given columns."""
    out: set = set()
    for row in rows or []:
        for col in cols:
            v = _norm(row.get(col) if isinstance(row, dict) else row)
            if v and not v.startswith("#"):
                out.add(v)
    return out


def context_from_csv(
    *,
    authorized: Iterable[dict] = (),          # config/authorized.csv (org allow, domains)
    authorized_code: Iterable[dict] = (),     # config/authorized_code.csv (org allow, code/tools)
    unauthorized_custom: Iterable[dict] = (), # config/unauthorized_custom.csv (org deny)
    unauthorized_code_custom: Iterable[dict] = (),  # org deny, code
    giggso_baseline: Iterable[dict] = (),     # config/unauthorized.csv — starter deny content;
                                               # folds into org_deny, no separate tier (ADR_2026-07-31)
) -> PolicyContext:
    """Org-scope PolicyContext from the existing CSV rows.

    Project/user scopes stay empty here — they require the policy DB
    (policy_queries.load_policy_context). The match key is a provider glob
    (domain OR tool id)."""
    return PolicyContext(
        org_approve=(
            _patterns(authorized, "name", "domain_pattern")
            | _patterns(authorized_code, "name", "pattern")
        ),
        org_deny=(
            _patterns(unauthorized_custom, "name", "domain")
            | _patterns(unauthorized_code_custom, "name", "pattern")
            | _patterns(giggso_baseline, "domain")
        ),
    )
