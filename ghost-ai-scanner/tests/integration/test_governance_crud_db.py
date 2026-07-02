# =============================================================
# FILE: tests/integration/test_governance_crud_db.py
# VERSION: 1.1.0
# UPDATED: 2026-07-01
# OWNER: Giggso Inc
# PURPOSE: Live-DB tests for the Provider Governance write-path server-
#          side authz (C8) + baseline-override guard (C1/C3/C4) + the
#          idempotent add + allow<->block flip (v1.1.0). Requires
#          DATABASE_URL. Creates and tears down its own org.
# =============================================================

import os
import sys
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from sqlalchemy import create_engine, delete, select
from sqlalchemy.orm import Session

from db.models_identity import Org, User
from db.models_policy import ApprovedTool, BlacklistedTool, GiggsoBaselineDeny
from db.governance_crud import (
    PolicyAuthzError, add_approved, add_blacklisted,
    move_to_allowed, move_to_blocked, is_giggso_blocked,
)

_ZBASE = "zbaseline-flip.ai"   # isolated Giggso-baseline domain for the flip test

URL = os.environ.get("DATABASE_URL", "")


def _run():
    eng = create_engine(URL, future=True)
    with Session(eng) as s:
        org = Org(slug="ztest-crud", display_name="Z", s3_bucket="b")
        s.add(org); s.flush()
        admin = User(org_id=org.id, email="admin@z.com", is_org_admin=True)
        member = User(org_id=org.id, email="member@z.com", is_org_admin=False)
        s.add_all([admin, member]); s.commit()
        try:
            # 1. non-admin cannot add an org-scope approve (C8)
            try:
                add_approved(s, actor=member, org_id=org.id, scope="org",
                             name="x", provider_pattern="x")
                assert False, "expected PolicyAuthzError"
            except PolicyAuthzError:
                s.rollback()

            # 2. admin can add an org approve
            row = add_approved(s, actor=admin, org_id=org.id, scope="org",
                               name="Copilot", provider_pattern="copilot")
            assert row.id is not None

            # 3. member can add to THEIR OWN user list
            row2 = add_approved(s, actor=member, org_id=org.id, scope="user",
                                user_id=member.id, name="Claude",
                                provider_pattern="claude.ai")
            assert row2.scope == "user"

            # 4. member CANNOT add to another user's list (C8)
            try:
                add_approved(s, actor=member, org_id=org.id, scope="user",
                             user_id=admin.id, name="bad", provider_pattern="bad")
                assert False, "expected PolicyAuthzError"
            except PolicyAuthzError:
                s.rollback()

            # 4b. ADMIN may manage another user's list (org-admin override)
            r = add_approved(s, actor=admin, org_id=org.id, scope="user",
                             user_id=member.id, name="Claude", provider_pattern="claude.ai")
            assert r.scope == "user" and r.user_id == member.id

            # 5. override with no reason → rejected by C3 guard
            try:
                add_approved(s, actor=admin, org_id=org.id, scope="org",
                             name="Ollama", provider_pattern="ollama",
                             overrides_giggso=True, reason="",
                             valid_until=date.today() + timedelta(days=30))
                assert False, "expected override rejection"
            except PolicyAuthzError:
                s.rollback()

            # 6. valid override → accepted
            ov = add_approved(s, actor=admin, org_id=org.id, scope="org",
                              name="Ollama", provider_pattern="ollama",
                              overrides_giggso=True,
                              reason="approved by security",
                              valid_until=date.today() + timedelta(days=30))
            assert ov.overrides_giggso is True and ov.approved_by == admin.id

            # 7. deny add works for admin
            b = add_blacklisted(s, actor=admin, org_id=org.id, scope="org",
                                domain="evil.com", severity="HIGH")
            assert b.id is not None

            # 8. idempotent add — a duplicate approve does NOT create a 2nd row
            first = add_approved(s, actor=admin, org_id=org.id, scope="org",
                                 name="Dup", provider_pattern="dup.ai")
            again = add_approved(s, actor=admin, org_id=org.id, scope="org",
                                 name="Dup", provider_pattern="dup.ai")
            assert first.id == again.id
            n = s.execute(select(ApprovedTool).where(
                ApprovedTool.org_id == org.id,
                ApprovedTool.domain_pattern == "dup.ai")).scalars().all()
            assert len(n) == 1, "duplicate approve row created"

            # 9. flip allow -> block (same scope), original approve gone
            move_to_blocked(s, actor=admin, org_id=org.id, approve_row_id=first.id)
            assert s.get(ApprovedTool, first.id) is None
            assert s.execute(select(BlacklistedTool).where(
                BlacklistedTool.org_id == org.id,
                BlacklistedTool.domain == "dup.ai")).scalars().first() is not None

            # 10. flip block -> allow, NON-baseline → plain approve (no override)
            nb = add_blacklisted(s, actor=admin, org_id=org.id, scope="org",
                                 domain="harmless.tool", severity="LOW")
            was_override = move_to_allowed(s, actor=admin, org_id=org.id,
                                           block_row_id=nb.id)
            assert was_override is False
            ap = s.execute(select(ApprovedTool).where(
                ApprovedTool.org_id == org.id,
                ApprovedTool.domain_pattern == "harmless.tool")).scalars().first()
            assert ap is not None and ap.overrides_giggso is False

            # 11. flip block -> allow for a GIGGSO-BASELINE provider:
            #     no reason → rejected by the guard; with reason → override.
            s.add(GiggsoBaselineDeny(domain=_ZBASE, severity="HIGH")); s.commit()
            assert is_giggso_blocked(s, _ZBASE) is True
            bl = add_blacklisted(s, actor=admin, org_id=org.id, scope="org",
                                 domain=_ZBASE, severity="HIGH")
            try:
                move_to_allowed(s, actor=admin, org_id=org.id, block_row_id=bl.id,
                                reason=None)
                assert False, "baseline flip without reason must be rejected (C3)"
            except PolicyAuthzError:
                s.rollback()
            bl2 = s.execute(select(BlacklistedTool).where(
                BlacklistedTool.org_id == org.id,
                BlacklistedTool.domain == _ZBASE)).scalars().first()
            was_override = move_to_allowed(s, actor=admin, org_id=org.id,
                                           block_row_id=bl2.id,
                                           reason="research use, approved")
            assert was_override is True
            ov2 = s.execute(select(ApprovedTool).where(
                ApprovedTool.org_id == org.id,
                ApprovedTool.domain_pattern == _ZBASE)).scalars().first()
            assert ov2 is not None and ov2.overrides_giggso is True
            assert ov2.valid_until is not None       # C4 expiry auto-applied

            print("PASS test_governance_crud_authz (11 checks)")
        finally:
            s.execute(delete(Org).where(Org.slug == "ztest-crud"))
            s.execute(delete(GiggsoBaselineDeny).where(GiggsoBaselineDeny.domain == _ZBASE))
            s.commit()


if __name__ == "__main__":
    if not URL:
        print("SKIP — DATABASE_URL not set"); sys.exit(0)
    _run()
    print("--- governance CRUD integration test passed ---")
