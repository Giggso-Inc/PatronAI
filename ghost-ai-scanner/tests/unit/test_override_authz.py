# =============================================================
# FILE: tests/unit/test_override_authz.py
# VERSION: 1.0.0
# UPDATED: 2026-06-29
# OWNER: Giggso Inc
# PURPOSE: Server-side Giggso-override authz guard (C1/C3/C4). Pure.
# =============================================================

import sys
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from db.override_authz import (
    OVERRIDE_MAX_DAYS, default_override_expiry, validate_override_request,
)

_OK = dict(is_org_admin=True, scope="org", reason="approved by security",
           approved_by="u1", valid_until=date.today() + timedelta(days=30))


def test_valid_override_passes():
    assert validate_override_request(**_OK) == []


def test_non_admin_rejected_c1():
    errs = validate_override_request(**{**_OK, "is_org_admin": False})
    assert any("C1" in e for e in errs)


def test_project_and_user_scope_now_allowed_c1prime():
    # C1' extends override to project/user scope (org-admin still required).
    assert validate_override_request(**{**_OK, "scope": "project"}) == []
    assert validate_override_request(**{**_OK, "scope": "user"}) == []


def test_invalid_scope_rejected():
    errs = validate_override_request(**{**_OK, "scope": "bogus"})
    assert any("scope" in e for e in errs)


def test_missing_reason_and_approver_rejected_c3():
    errs = validate_override_request(**{**_OK, "reason": "  ", "approved_by": None})
    assert sum("C3" in e for e in errs) == 2


def test_missing_expiry_rejected_c4():
    errs = validate_override_request(**{**_OK, "valid_until": None})
    assert any("C4" in e for e in errs)


def test_expiry_beyond_max_rejected_c4():
    far = date.today() + timedelta(days=OVERRIDE_MAX_DAYS + 1)
    errs = validate_override_request(**{**_OK, "valid_until": far})
    assert any("C4" in e for e in errs)


def test_default_expiry_is_90_days():
    assert default_override_expiry(date(2026, 1, 1)) == date(2026, 1, 1) + timedelta(days=90)
