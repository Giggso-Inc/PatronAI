# =============================================================
# FILE: tests/integration/test_project_crud_db.py
# VERSION: 1.0.0
# UPDATED: 2026-06-30
# OWNER: Giggso Inc
# PURPOSE: Live-DB tests for project management + per-scope list ops (F4
#          backend). Requires DATABASE_URL. Self-cleaning org.
# =============================================================

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from sqlalchemy import create_engine, delete
from sqlalchemy.orm import Session

from db.models_identity import Org, User
from db.models_policy import ApprovedTool
from db.governance_crud import (
    PolicyAuthzError, add_approved, add_project_member, create_project,
    list_org_users, list_scope, list_projects,
)

URL = os.environ.get("DATABASE_URL", "")
SLUG = "ztest-project"


def _run():
    eng = create_engine(URL, future=True)
    with Session(eng) as s:
        s.execute(delete(Org).where(Org.slug == SLUG)); s.commit()
        org = Org(slug=SLUG, display_name="Z", s3_bucket="b"); s.add(org); s.flush()
        admin = User(org_id=org.id, email="a@zt.com", is_org_admin=True)
        member = User(org_id=org.id, email="m@zt.com", is_org_admin=False)
        s.add_all([admin, member]); s.commit()
        try:
            # non-admin cannot create a project
            try:
                create_project(s, actor=member, org_id=org.id, slug="eng", display_name="Eng")
                assert False
            except PolicyAuthzError:
                s.rollback()

            project = create_project(s, actor=admin, org_id=org.id, slug="eng", display_name="Engineering")
            add_project_member(s, actor=admin, project_id=project.id, user_id=member.id)

            projects = list_projects(s, org.id)
            assert len(projects) == 1 and projects[0][1] == 1   # one project, one member
            assert len(list_org_users(s, org.id)) == 2

            # project-scope approve, then list it back
            add_approved(s, actor=admin, org_id=org.id, scope="project", project_id=project.id,
                         name="LangChain", provider_pattern="langchain")
            rows = list_scope(s, ApprovedTool, org_id=org.id, scope="project", project_id=project.id)
            assert len(rows) == 1 and rows[0].domain_pattern == "langchain"
            print("PASS project_crud + list_scope (4 checks)")
        finally:
            s.execute(delete(Org).where(Org.slug == SLUG)); s.commit()


if __name__ == "__main__":
    if not URL:
        print("SKIP — DATABASE_URL not set"); sys.exit(0)
    _run()
    print("--- project CRUD integration test passed ---")
