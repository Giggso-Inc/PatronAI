# =============================================================
# FILE: tests/integration/test_raven_enterprise_users_sync_db.py
# VERSION: 1.0.0
# UPDATED: 2026-08-17
# OWNER: Giggso Inc
# PURPOSE: Live-DB tests for POST /raven-enterprise/users/sync
#          (routers/raven_enterprise_users.py). Sibling of
#          test_raven_enterprise_sync_db.py, which covers the project/member
#          side. Requires DATABASE_URL. Self-cleaning orgs.
#
#          Driven through the HTTP layer with TestClient rather than calling
#          governance_crud directly, because the contract under review is the
#          STATUS CODES — 404 on an unknown org, 409 on a cross-org email — and
#          those live in the router, not the CRUD. The auth dependency is
#          overridden: both layers (bearer API_KEY and the X-Raven-Identity
#          JWT) are covered by tests/unit/test_api_auth.py, and re-proving them
#          here would only test FastAPI's dependency wiring.
#
#          What this exists to stop regressing, per PR review:
#            1. the row is actually COMMITTED (get_or_create_user_for_sync only
#               flushes, and get_session() does not commit on context exit —
#               the single easiest way to silently lose the write)
#            2. idempotency, so retries and no-op role changes are safe
#            3. is_admin flips in BOTH directions (a demotion that does not
#               demote is the dangerous half)
#            4. 404 on an unknown org_slug — a typo must not create an org
#            5. 409 on an email owned by a different org — never silently
#               re-home someone else's identity
# =============================================================

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from sqlalchemy import create_engine, delete, select
from sqlalchemy.orm import Session

from db.models_identity import Org, User

URL = os.environ.get("DATABASE_URL", "")
SLUG = "ztest-users-sync"
OTHER_SLUG = "ztest-users-sync-other"
EMAIL = "zsync-user@zt.com"
CROSS_EMAIL = "zsync-cross@zt.com"


def _client():
    """App + auth override. Imported lazily so a missing DATABASE_URL exits
    before FastAPI pulls in the whole app graph."""
    from fastapi.testclient import TestClient

    from api import app
    from routers._raven_identity import verify_ravenhub_identity

    # The actor is only ever the JWT subject for this endpoint — the org comes
    # from the payload — so a fixed stub loses no coverage. See the router
    # header for why that design choice was made.
    app.dependency_overrides[verify_ravenhub_identity] = lambda: "hub@service.local"
    return TestClient(app)


def _post(c, **body):
    return c.post("/raven-enterprise/users/sync", json=body)


def _run():
    eng = create_engine(URL, future=True)
    c = _client()

    with Session(eng) as s:
        s.execute(delete(User).where(User.email.in_([EMAIL, CROSS_EMAIL])))
        s.execute(delete(Org).where(Org.slug.in_([SLUG, OTHER_SLUG])))
        s.commit()
        org = Org(slug=SLUG, display_name="Z", s3_bucket="b")
        other = Org(slug=OTHER_SLUG, display_name="Z2", s3_bucket="b2")
        s.add_all([org, other])
        s.commit()

        try:
            # 1. Create. `created` must be True, and — the load-bearing part —
            #    the row must be readable from a SEPARATE session, which is what
            #    proves the endpoint committed rather than merely flushed.
            r = _post(c, email=EMAIL, org_slug=SLUG, is_admin=False,
                      display_name="Z Sync")
            assert r.status_code == 200, (r.status_code, r.text)
            assert r.json()["created"] is True, r.json()
            assert r.json()["is_org_admin"] is False

            with Session(eng) as fresh:
                row = fresh.execute(
                    select(User).where(User.email == EMAIL)
                ).scalar_one_or_none()
                assert row is not None, "row not committed — endpoint only flushed"
                assert row.org_id == org.id
                assert row.is_org_admin is False

            # 2. Idempotent re-sync: same payload returns the SAME user and
            #    reports created=False. Retries and no-op role changes are safe.
            r2 = _post(c, email=EMAIL, org_slug=SLUG, is_admin=False)
            assert r2.status_code == 200, r2.text
            assert r2.json()["created"] is False
            assert r2.json()["user_id"] == r.json()["user_id"]

            with Session(eng) as fresh:
                n = len(fresh.execute(
                    select(User).where(User.email == EMAIL)
                ).scalars().all())
                assert n == 1, f"re-sync duplicated the row ({n} found)"

            # 3. Promote: is_admin False -> True.
            r3 = _post(c, email=EMAIL, org_slug=SLUG, is_admin=True)
            assert r3.status_code == 200 and r3.json()["is_org_admin"] is True
            with Session(eng) as fresh:
                assert fresh.execute(
                    select(User.is_org_admin).where(User.email == EMAIL)
                ).scalar_one() is True

            # 4. Demote: True -> False. The direction that matters most — a
            #    sync that only ever grants would leave a demoted user admin.
            r4 = _post(c, email=EMAIL, org_slug=SLUG, is_admin=False)
            assert r4.status_code == 200 and r4.json()["is_org_admin"] is False
            with Session(eng) as fresh:
                assert fresh.execute(
                    select(User.is_org_admin).where(User.email == EMAIL)
                ).scalar_one() is False

            # 5. Unknown org -> 404, and no org is created. Strict lookup, never
            #    ensure_org, so a typo cannot silently spawn an org.
            r5 = _post(c, email="zsync-nobody@zt.com",
                       org_slug="ztest-does-not-exist", is_admin=False)
            assert r5.status_code == 404, (r5.status_code, r5.text)
            with Session(eng) as fresh:
                assert fresh.execute(
                    select(Org).where(Org.slug == "ztest-does-not-exist")
                ).scalar_one_or_none() is None, "404 path created an org"

            # 6. Cross-org email -> 409. users.email is globally unique, so an
            #    address owned by another org must be refused, not re-homed.
            with Session(eng) as seed:
                seed.add(User(org_id=other.id, email=CROSS_EMAIL, is_org_admin=False))
                seed.commit()
            r6 = _post(c, email=CROSS_EMAIL, org_slug=SLUG, is_admin=True)
            assert r6.status_code == 409, (r6.status_code, r6.text)
            with Session(eng) as fresh:
                stayed = fresh.execute(
                    select(User).where(User.email == CROSS_EMAIL)
                ).scalar_one()
                assert stayed.org_id == other.id, "409 still moved the user"
                assert stayed.is_org_admin is False, "409 still applied is_admin"

            # 7. display_name fills only when empty — never clobbers a name the
            #    user or an earlier seed already set.
            r7 = _post(c, email=EMAIL, org_slug=SLUG, is_admin=False,
                       display_name="Should Not Overwrite")
            assert r7.status_code == 200
            with Session(eng) as fresh:
                assert fresh.execute(
                    select(User.display_name).where(User.email == EMAIL)
                ).scalar_one() == "Z Sync"

            print("PASS raven_enterprise users/sync (commit, idempotency, "
                  "promote, demote, 404 unknown org, 409 cross-org, "
                  "display_name preserved — 7 checks)")
        finally:
            with Session(eng) as cleanup:
                cleanup.execute(delete(User).where(User.email.in_([EMAIL, CROSS_EMAIL])))
                cleanup.execute(delete(Org).where(Org.slug.in_([SLUG, OTHER_SLUG])))
                cleanup.commit()


if __name__ == "__main__":
    if not URL:
        print("SKIP — DATABASE_URL not set"); sys.exit(0)
    _run()
    print("--- raven_enterprise users/sync integration test passed ---")
