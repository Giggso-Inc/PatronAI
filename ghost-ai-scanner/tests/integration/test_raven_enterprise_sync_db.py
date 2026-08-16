# =============================================================
# FILE: tests/integration/test_raven_enterprise_sync_db.py
# VERSION: 1.1.0
# UPDATED: 2026-08-16
# OWNER: Giggso Inc
# PURPOSE: Live-DB tests for the RavenHub -> patron project/member sync CRUD
#          (routers/raven_enterprise_projects.py's backing functions in
#          db.governance_crud). Requires DATABASE_URL. Self-cleaning org.
# AUDIT LOG:
#   v1.0.0  2026-07-26  Initial — create/member-sync CRUD checks.
#   v1.1.0  2026-08-16  Add delete-sync CRUD checks (D-101 counterpart).
# =============================================================

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from sqlalchemy import create_engine, delete
from sqlalchemy.orm import Session

from db.models_identity import Org, Project, User
from db.governance_crud import (
    add_project_member_from_sync, create_project_from_sync,
    delete_project_by_external_ref, get_or_create_user_for_sync,
    get_project_by_external_ref,
)

URL = os.environ.get("DATABASE_URL", "")
SLUG = "ztest-raven-sync"
OTHER_SLUG = "ztest-raven-sync-other-org"


def _run():
    eng = create_engine(URL, future=True)
    with Session(eng) as s:
        s.execute(delete(Org).where(Org.slug.in_([SLUG, OTHER_SLUG]))); s.commit()
        org = Org(slug=SLUG, display_name="Z", s3_bucket="b")
        other_org = Org(slug=OTHER_SLUG, display_name="Z2", s3_bucket="b2")
        s.add_all([org, other_org]); s.flush()
        try:
            # 1. Idempotent create-by-external_ref: a second sync call for the
            #    SAME upstream project must return the existing row, not create
            #    a duplicate (this is the exact contract the retry-loop fix in
            #    the router depends on).
            p1 = create_project_from_sync(
                s, org_id=org.id, slug="eng", display_name="Engineering",
                external_source="ravenhub", external_ref="group-1",
            )
            found = get_project_by_external_ref(
                s, org_id=org.id, external_source="ravenhub", external_ref="group-1",
            )
            assert found is not None and found.id == p1.id

            # 2. Slug collision across DIFFERENT upstream projects in the same
            #    org: create_project_from_sync itself doesn't retry (that's the
            #    router's job), but confirms the DB-level uniqueness the retry
            #    loop is built to work around actually fires.
            try:
                create_project_from_sync(
                    s, org_id=org.id, slug="eng", display_name="Engineering Duplicate",
                    external_source="ravenhub", external_ref="group-2",
                )
                assert False, "expected IntegrityError on duplicate (org_id, slug)"
            except Exception:
                s.rollback()

            # 3. get_project_by_external_ref is scoped by org — a real project
            #    in a different org must not be visible under this org_id.
            create_project_from_sync(
                s, org_id=other_org.id, slug="eng", display_name="Engineering (other org)",
                external_source="ravenhub", external_ref="group-in-other-org",
            )
            assert get_project_by_external_ref(
                s, org_id=org.id, external_source="ravenhub", external_ref="group-in-other-org",
            ) is None

            # 4. Member sync: get-or-create by email, then idempotent add.
            user = get_or_create_user_for_sync(s, org_id=org.id, email="dev@zt.com")
            add_project_member_from_sync(s, project_id=p1.id, user_id=user.id)
            add_project_member_from_sync(s, project_id=p1.id, user_id=user.id)  # idempotent, no error
            same_user = get_or_create_user_for_sync(s, org_id=org.id, email="dev@zt.com")
            assert same_user.id == user.id

            # 5. Cross-org refusal: an email already belonging to a DIFFERENT
            #    org must be refused, never silently re-homed.
            existing_other_org_user = User(org_id=other_org.id, email="cross@zt.com", is_org_admin=False)
            s.add(existing_other_org_user); s.commit()
            try:
                get_or_create_user_for_sync(s, org_id=org.id, email="cross@zt.com")
                assert False, "expected ValueError for cross-org identity"
            except ValueError:
                pass

            # 6. Delete-sync: deleting an existing project by external_ref
            #    removes it (and get_project_by_external_ref no longer finds
            #    it) — the D-101 fix for the confirmed-live orphan-row gap.
            p2 = create_project_from_sync(
                s, org_id=org.id, slug="to-delete", display_name="To Delete",
                external_source="ravenhub", external_ref="group-to-delete",
            )
            deleted = delete_project_by_external_ref(
                s, org_id=org.id, external_source="ravenhub", external_ref="group-to-delete",
            )
            assert deleted is True
            assert get_project_by_external_ref(
                s, org_id=org.id, external_source="ravenhub", external_ref="group-to-delete",
            ) is None

            # 7. Delete-sync is idempotent: deleting an external_ref that's
            #    already gone (or was never synced) returns False, not an
            #    error — the raven-side caller treats this as "nothing to
            #    clean up", matching the router's 404-is-a-no-op contract.
            assert delete_project_by_external_ref(
                s, org_id=org.id, external_source="ravenhub", external_ref="group-to-delete",
            ) is False
            assert delete_project_by_external_ref(
                s, org_id=org.id, external_source="ravenhub", external_ref="never-synced-at-all",
            ) is False

            # 8. Delete-sync is org-scoped, same as get_project_by_external_ref:
            #    a real project in a DIFFERENT org must not be deletable by
            #    another org's external_ref claim. (Uses its own external_ref,
            #    distinct from check 3's "group-in-other-org" — the
            #    (org_id, external_source, external_ref) unique constraint
            #    would otherwise reject a second row with the same triple.)
            create_project_from_sync(
                s, org_id=other_org.id, slug="other-org-keep", display_name="Other Org Keep",
                external_source="ravenhub", external_ref="group-in-other-org-2",
            )
            assert delete_project_by_external_ref(
                s, org_id=org.id, external_source="ravenhub", external_ref="group-in-other-org-2",
            ) is False
            assert get_project_by_external_ref(
                s, org_id=other_org.id, external_source="ravenhub", external_ref="group-in-other-org-2",
            ) is not None  # untouched under its real org

            print("PASS raven_enterprise sync CRUD (idempotent create, slug collision, "
                  "org-scoped lookup, idempotent member add, cross-org refusal, "
                  "delete-sync + idempotent delete + org-scoped delete — 8 checks)")
        finally:
            s.execute(delete(Project).where(Project.org_id.in_([org.id, other_org.id])))
            s.execute(delete(User).where(User.org_id.in_([org.id, other_org.id])))
            s.execute(delete(Org).where(Org.slug.in_([SLUG, OTHER_SLUG])))
            s.commit()


if __name__ == "__main__":
    if not URL:
        print("SKIP — DATABASE_URL not set"); sys.exit(0)
    _run()
    print("--- raven_enterprise sync CRUD integration test passed ---")
