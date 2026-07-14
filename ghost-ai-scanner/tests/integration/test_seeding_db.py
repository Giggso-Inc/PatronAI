# =============================================================
# FILE: tests/integration/test_seeding_db.py
# VERSION: 2.0.0
# UPDATED: 2026-06-30
# OWNER: Giggso Inc
# PURPOSE: Live-DB tests for the S3->DB seed (F1/P0/P1) + identity (F2).
#          ISOLATED: uses a ztest org + unique ztest domains so it never
#          collides with or deletes real seeded data / production markers.
#          Requires DATABASE_URL.
# =============================================================

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from sqlalchemy import create_engine, delete
from sqlalchemy.orm import Session

from db.models_identity import Org
from db.models_policy import GiggsoBaselineDeny
from db.policy_queries import get_identity, load_policy_context
from db.seeding import seed_all

URL = os.environ.get("DATABASE_URL", "")
SLUG = "ztest-seed"
GIGGSO = ["ztest-giggso-a.example", "ztest-giggso-b.example"]

_DATA = dict(
    org_slug=SLUG, org_name="Z Seed", bucket="patronai-test-data",
    users_map={"support@z.com": {"is_admin": True}, "bob@z.com": {"is_admin": False}},
    scanned_emails=["k.sanjaykumar@z.com", "scan2@z.com"],   # P1: members from findings
    giggso_rows=[{"domain": GIGGSO[0], "severity": "HIGH"},
                 {"domain": GIGGSO[1], "severity": "MEDIUM"}],
    allow_rows=[{"domain_pattern": "ztest-allow-a"}],
    allow_code_rows=[{"pattern": "ztest-allow-b"}],
    deny_rows=[{"domain": "ztest-deny-a"}],
    deny_code_rows=[{"pattern": "ztest-deny-b"}],
)


def _cleanup(s):
    # Only our isolated org + our unique giggso domains. NEVER prod markers.
    s.execute(delete(Org).where(Org.slug == SLUG))
    s.execute(delete(GiggsoBaselineDeny).where(GiggsoBaselineDeny.domain.in_(GIGGSO)))
    s.commit()


def _run():
    eng = create_engine(URL, future=True)
    with Session(eng) as s:
        _cleanup(s)
        try:
            r1 = seed_all(s, **_DATA)
            assert r1["users"] == 4, r1          # 2 auth + 2 scanned
            assert r1["giggso"] == 2, r1
            assert r1["approved"] == 2 and r1["blacklisted"] == 2, r1
            print(f"PASS seed_all populated: {r1}")

            # idempotent by DATA — second run inserts nothing new (no dupes)
            r2 = seed_all(s, **_DATA)
            assert r2 == {**r2, "users": 0, "giggso": 0, "approved": 0, "blacklisted": 0}, r2
            print("PASS seed_all idempotent (0 new on re-run)")

            # auth user = admin; scanned user = member, both with display_name
            admin, org_id, _ = get_identity(s, "support@z.com")
            assert admin.is_org_admin is True and admin.display_name
            scanned, _, _ = get_identity(s, "k.sanjaykumar@z.com")
            assert scanned is not None and scanned.is_org_admin is False
            assert scanned.display_name == "K Sanjaykumar", scanned.display_name
            print("PASS users union + display_name")

            ctx = load_policy_context(s, org_id=org_id, user_id=admin.id)
            assert "ztest-allow-a" in ctx.org_approve and "ztest-allow-b" in ctx.org_approve
            assert "ztest-deny-a" in ctx.org_deny and "ztest-deny-b" in ctx.org_deny
            assert all(g in ctx.giggso_deny for g in GIGGSO)
            print("PASS load_policy_context reflects seed")
        finally:
            _cleanup(s)


if __name__ == "__main__":
    if not URL:
        print("SKIP — DATABASE_URL not set"); sys.exit(0)
    _run()
    print("--- seeding + identity integration tests passed ---")
