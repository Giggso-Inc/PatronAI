# =============================================================
# FILE: src/db/override_authz.py
# VERSION: 1.0.0
# UPDATED: 2026-06-29
# OWNER: Giggso Inc
# PURPOSE: Server-side authorisation guard for the Giggso baseline
#          override (Phase E, security conditions C1/C3/C4/C8). PURE —
#          enforce these BEFORE any DB write; the DB CHECK is the second
#          line of defence, this is the first. Never trust a client flag.
# =============================================================

import datetime as _dt

OVERRIDE_MAX_DAYS = 90  # C4 — no permanent baseline overrides


def default_override_expiry(today=None):
    """C4: overrides expire — default 90 days out."""
    today = today or _dt.date.today()
    return today + _dt.timedelta(days=OVERRIDE_MAX_DAYS)


def validate_override_request(*, is_org_admin: bool, scope: str,
                              reason: str, approved_by, valid_until=None,
                              today=None) -> list:
    """Return a list of human-readable violations (empty == allowed).

    Enforces: C1' org-admin at org/project/user scope (see migration 0003);
    C3 reason + approver; C4 mandatory expiry ≤ 90 days. Callers MUST refuse
    the write when this returns a non-empty list."""
    today = today or _dt.date.today()
    errs: list = []
    if not is_org_admin:
        errs.append("C1': only an org admin may override a Giggso baseline block")
    if scope not in ("org", "project", "user"):
        errs.append("C1': override scope must be org, project, or user")
    if not (reason or "").strip():
        errs.append("C3: a written reason is required for an override")
    if not approved_by:
        errs.append("C3: an approver identity is required for an override")
    if valid_until is None:
        errs.append("C4: an expiry date is required (no permanent overrides)")
    elif valid_until > today + _dt.timedelta(days=OVERRIDE_MAX_DAYS):
        errs.append(f"C4: override expiry may not exceed {OVERRIDE_MAX_DAYS} days")
    elif valid_until < today:
        errs.append("C4: override expiry is in the past")
    return errs
