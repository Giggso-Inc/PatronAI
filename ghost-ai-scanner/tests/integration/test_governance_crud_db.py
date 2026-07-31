# =============================================================
# FILE: tests/integration/test_governance_crud_db.py
# VERSION: 2.0.0
# UPDATED: 2026-07-31
# OWNER: Giggso Inc
# PURPOSE: Live-DB tests for the Provider Governance write-path server-
#          side authz (C8) + idempotent add + fully-open allow<->block flip
#          + the OQ-4 opposite-polarity guard (ADR_2026-07-31). Requires
#          DATABASE_URL. Creates and tears down its own org.
# AUDIT LOG:
#   v1.1.0  2026-07-01  Baseline-override guard (C1/C3/C4) + deny-override
#                       (D1-D7) checks.
#   v2.0.0  2026-07-31  ADR_2026-07-31: removed all Giggso-baseline/
#                       override/deny-override checks (that machinery no
#                       longer exists). Added OQ-4 opposite-polarity checks.
# =============================================================

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from sqlalchemy import create_engine, delete, select
from sqlalchemy.orm import Session

from db.models_identity import Org, User
from db.models_policy import ApprovedTool, BlacklistedTool
from db.governance_crud import (
    PolicyAuthzError, add_approved, add_blacklisted,
    move_to_allowed, move_to_blocked,
)

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

            # 5. deny add works for admin — fully open, no reason required
            b = add_blacklisted(s, actor=admin, org_id=org.id, scope="org",
                                domain="evil.com", severity="HIGH")
            assert b.id is not None

            # 6. idempotent add — a duplicate approve does NOT create a 2nd row
            first = add_approved(s, actor=admin, org_id=org.id, scope="org",
                                 name="Dup", provider_pattern="dup.ai")
            again = add_approved(s, actor=admin, org_id=org.id, scope="org",
                                 name="Dup", provider_pattern="dup.ai")
            assert first.id == again.id
            n = s.execute(select(ApprovedTool).where(
                ApprovedTool.org_id == org.id,
                ApprovedTool.domain_pattern == "dup.ai")).scalars().all()
            assert len(n) == 1, "duplicate approve row created"

            # 7. OQ-4 — cannot add a deny for a pattern already approved at
            #    the SAME scope (opposite polarity conflict).
            try:
                add_blacklisted(s, actor=admin, org_id=org.id, scope="org",
                                domain="dup.ai", severity="HIGH")
                assert False, "OQ-4: opposite-polarity conflict must be refused"
            except PolicyAuthzError:
                s.rollback()

            # 8. flip allow -> block (same scope) — fully open, no reason.
            #    The flip deletes the approve row first so OQ-4 never
            #    false-positives against the row being replaced.
            move_to_blocked(s, actor=admin, org_id=org.id, approve_row_id=first.id)
            assert s.get(ApprovedTool, first.id) is None
            assert s.execute(select(BlacklistedTool).where(
                BlacklistedTool.org_id == org.id,
                BlacklistedTool.domain == "dup.ai")).scalars().first() is not None

            # 9. flip block -> allow — fully open, no reason/expiry required.
            nb = add_blacklisted(s, actor=admin, org_id=org.id, scope="org",
                                 domain="harmless.tool", severity="LOW")
            move_to_allowed(s, actor=admin, org_id=org.id, block_row_id=nb.id)
            ap = s.execute(select(ApprovedTool).where(
                ApprovedTool.org_id == org.id,
                ApprovedTool.domain_pattern == "harmless.tool")).scalars().first()
            assert ap is not None

            # 10. cross-org write refused (PR#8 defence-in-depth): an org admin
            #     cannot write into a DIFFERENT org even if org_id is forged.
            import uuid as _uuid
            try:
                add_approved(s, actor=admin, org_id=_uuid.uuid4(), scope="org",
                             name="x", provider_pattern="cross.org")
                assert False, "cross-org write should be refused"
            except PolicyAuthzError:
                s.rollback()

            print("PASS test_governance_crud_authz (10 checks)")
        finally:
            s.execute(delete(Org).where(Org.slug == "ztest-crud"))
            s.commit()


if __name__ == "__main__":
    if not URL:
        print("SKIP — DATABASE_URL not set"); sys.exit(0)
    _run()
    print("--- governance CRUD integration test passed ---")
