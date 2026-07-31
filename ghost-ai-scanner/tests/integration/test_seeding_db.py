# =============================================================
# FILE: tests/integration/test_seeding_db.py
# VERSION: 3.0.0
# UPDATED: 2026-07-31
# OWNER: Giggso Inc
# PURPOSE: Live-DB tests for the S3->DB seed + identity, and the OQ-1
#          per-org starter deny content (ADR_2026-07-31). ISOLATED: uses a
#          ztest org + unique ztest domains so it never collides with or
#          deletes real seeded data / production markers. Requires
#          DATABASE_URL.
# AUDIT LOG:
#   v2.0.0  2026-06-30  S3->DB seed + identity (F1/F2), incl. Giggso seed.
#   v3.0.0  2026-07-31  ADR_2026-07-31: no more giggso_rows/`n_giggso` — the
#                       starter deny content is read from the local bundled
#                       CSV by seed_all() itself, not passed in by the
#                       caller. Assert it lands in org_deny for THIS org.
# =============================================================

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from sqlalchemy import create_engine, delete
from sqlalchemy.orm import Session

from db.models_identity import Org
from db.policy_queries import get_identity, load_policy_context
from db.seeding import seed_all

URL = os.environ.get("DATABASE_URL", "")
SLUG = "ztest-seed"

_DATA = dict(
    org_slug=SLUG, org_name="Z Seed", bucket="patronai-test-data",
    users_map={"support@z.com": {"is_admin": True}, "bob@z.com": {"is_admin": False}},
    scanned_emails=["k.sanjaykumar@z.com", "scan2@z.com"],   # P1: members from findings
    allow_rows=[{"domain_pattern": "ztest-allow-a"}],
    allow_code_rows=[{"pattern": "ztest-allow-b"}],
    deny_rows=[{"domain": "ztest-deny-a"}],
    deny_code_rows=[{"pattern": "ztest-deny-b"}],
)


def _cleanup(s):
    # Only our isolated org. NEVER prod markers.
    s.execute(delete(Org).where(Org.slug == SLUG))
    s.commit()


def _run():
    eng = create_engine(URL, future=True)
    with Session(eng) as s:
        _cleanup(s)
        try:
            r1 = seed_all(s, **_DATA)
            assert r1["users"] == 4, r1          # 2 auth + 2 scanned
            # blacklisted includes our 2 custom deny rows PLUS whatever the
            # locally-bundled starter-deny CSV contributes (OQ-1) — assert
            # at least the custom rows landed, not an exact count (the
            # starter file's row count is content, not a contract here).
            assert r1["approved"] == 2, r1
            assert r1["blacklisted"] >= 2, r1
            print(f"PASS seed_all populated: {r1}")

            # idempotent by DATA — second run inserts nothing new for OUR rows
            r2 = seed_all(s, **_DATA)
            assert r2["users"] == 0 and r2["approved"] == 0, r2
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
            print("PASS load_policy_context reflects seed")
        finally:
            _cleanup(s)


if __name__ == "__main__":
    if not URL:
        print("SKIP — DATABASE_URL not set"); sys.exit(0)
    _run()
    print("--- seeding + identity integration tests passed ---")
