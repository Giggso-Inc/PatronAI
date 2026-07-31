# =============================================================
# FILE: tests/integration/test_policy_db.py
# VERSION: 2.0.0
# UPDATED: 2026-07-31
# OWNER: Giggso Inc
# PURPOSE: Live-DB tests for the Postgres policy backend:
#          load_policy_context (scope + expiry routing) under the
#          ADR_2026-07-31 scope-first waterfall — no Giggso baseline, no
#          override tiers. Requires DATABASE_URL (skips otherwise).
#          Cleans up after itself.
# AUDIT LOG:
#   v1.0.0  2026-06-29  Initial (giggso override routing).
#   v2.0.0  2026-07-31  ADR_2026-07-31: removed the Giggso baseline seed +
#                       override-routing test; PolicyContext no longer has
#                       those fields.
# =============================================================

import os
import sys
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from db.models_identity import Org, Project, ProjectMember, User
from db.models_policy import ApprovedTool, BlacklistedTool
from db.policy_queries import load_policy_context
from scoring.policy import policy_tier

URL = os.environ.get("DATABASE_URL", "")


def _engine():
    return create_engine(URL, future=True)


def test_load_policy_context_routes_scopes_and_expiry():
    """org/project/user approve + deny + expiry routing."""
    eng = _engine()
    with Session(eng) as s:
        try:
            org = Org(slug="ztest-org", display_name="Z", s3_bucket="b")
            s.add(org); s.flush()
            user = User(org_id=org.id, email="z@test.com")
            s.add(user); s.flush()
            project = Project(org_id=org.id, slug="zproject", display_name="Z Project")
            s.add(project); s.flush()
            s.add(ProjectMember(project_id=project.id, user_id=user.id)); s.flush()

            s.add_all([
                ApprovedTool(org_id=org.id, scope="org", name="Copilot",
                             domain_pattern="copilot"),
                ApprovedTool(org_id=org.id, scope="project", project_id=project.id,
                             name="LangChain", domain_pattern="langchain"),
                ApprovedTool(org_id=org.id, scope="user", user_id=user.id,
                             name="Claude", domain_pattern="claude.ai"),
                # expired user ack — must be ignored
                ApprovedTool(org_id=org.id, scope="user", user_id=user.id,
                             name="Old", domain_pattern="expired.ai",
                             valid_until=date.today() - timedelta(days=1)),
                BlacklistedTool(org_id=org.id, scope="org", domain="evil.com",
                                severity="HIGH"),
                BlacklistedTool(org_id=org.id, scope="project", project_id=project.id,
                                domain="projbad.ai", severity="HIGH"),
            ])
            s.flush()

            ctx = load_policy_context(
                s, org_id=org.id, user_id=user.id, project_ids=[project.id]
            )
            assert "copilot" in ctx.org_approve
            assert "langchain" in ctx.project_approve
            assert "claude.ai" in ctx.user_ack
            assert "expired.ai" not in ctx.user_ack          # expiry honoured
            assert "evil.com" in ctx.org_deny
            assert "projbad.ai" in ctx.project_deny

            # ADR_2026-07-31: scope-first — user's own allow beats org deny.
            assert policy_tier("claude.ai", ctx) == "user_ack"
            assert policy_tier("evil.com", ctx) == "org_deny"
            assert policy_tier("projbad.ai", ctx) == "project_deny"
        finally:
            s.rollback()  # leave the DB clean


if __name__ == "__main__":
    if not URL:
        print("SKIP — DATABASE_URL not set")
        sys.exit(0)
    test_load_policy_context_routes_scopes_and_expiry()
    print("PASS test_load_policy_context_routes_scopes_and_expiry")
    print("--- policy DB integration tests passed ---")
