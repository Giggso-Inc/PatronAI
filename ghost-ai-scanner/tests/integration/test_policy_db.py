# =============================================================
# FILE: tests/integration/test_policy_db.py
# VERSION: 1.0.0
# UPDATED: 2026-06-29
# OWNER: Giggso Inc
# PURPOSE: Live-DB tests for the Postgres policy backend (Phase C):
#          load_policy_context (scope + expiry + override routing) and
#          the idempotent Giggso baseline seed. Requires DATABASE_URL
#          (skips otherwise). Cleans up after itself.
# =============================================================

import os
import sys
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from sqlalchemy import create_engine, delete
from sqlalchemy.orm import Session

from db.models_identity import Org, Project, ProjectMember, User
from db.models_policy import (
    ApprovedTool, BlacklistedTool, GiggsoBaselineDeny, SchemaMigration,
)
from db.policy_queries import (
    GIGGSO_SEED_MARKER, load_policy_context, seed_giggso_baseline,
)

URL = os.environ.get("DATABASE_URL", "")


def _engine():
    return create_engine(URL, future=True)


def test_load_policy_context_routes_scopes_and_expiry():
    """org/project/user approve, deny, expiry, and override routing."""
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
                # guarded giggso overrides at org / project / user scope
                ApprovedTool(org_id=org.id, scope="org", name="Ollama",
                             domain_pattern="ollama", overrides_giggso=True,
                             reason="approved by security", approved_by=user.id),
                ApprovedTool(org_id=org.id, scope="project", project_id=project.id,
                             name="ProjTool", domain_pattern="projtool", overrides_giggso=True,
                             reason="research", approved_by=user.id),
                ApprovedTool(org_id=org.id, scope="user", user_id=user.id,
                             name="UserTool", domain_pattern="usertool", overrides_giggso=True,
                             reason="research", approved_by=user.id),
                BlacklistedTool(org_id=org.id, scope="org", domain="evil.com",
                                severity="HIGH"),
            ])
            s.add_all([
                GiggsoBaselineDeny(domain="ollama", severity="MEDIUM"),
                GiggsoBaselineDeny(domain="badmodel.ai", severity="HIGH"),
                GiggsoBaselineDeny(domain="projtool", severity="HIGH"),
                GiggsoBaselineDeny(domain="usertool", severity="HIGH"),
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
            assert "ollama" in ctx.giggso_deny
            assert "ollama" in ctx.giggso_override            # routed to override (org)
            assert "ollama" not in ctx.org_approve            # NOT a plain approve
            assert "projtool" in ctx.giggso_override_project  # project-scope override
            assert "usertool" in ctx.giggso_override_user     # user-scope override
            assert "badmodel.ai" in ctx.giggso_deny
        finally:
            s.rollback()  # leave the DB clean


def test_giggso_seed_is_idempotent():
    eng = _engine()
    with Session(eng) as s:
        # ensure a clean marker for a repeatable test
        s.execute(delete(SchemaMigration).where(
            SchemaMigration.version == GIGGSO_SEED_MARKER))
        s.execute(delete(GiggsoBaselineDeny).where(
            GiggsoBaselineDeny.domain == "seedtest.ai"))
        s.commit()
        try:
            rows = [{"name": "Seed", "domain": "seedtest.ai", "severity": "HIGH",
                     "category": "LLM", "port": "", "notes": "x"}]
            first = seed_giggso_baseline(s, rows)
            second = seed_giggso_baseline(s, rows)   # marker now set → no-op
            assert first == 1
            assert second == 0
        finally:
            s.execute(delete(SchemaMigration).where(
                SchemaMigration.version == GIGGSO_SEED_MARKER))
            s.execute(delete(GiggsoBaselineDeny).where(
                GiggsoBaselineDeny.domain == "seedtest.ai"))
            s.commit()


if __name__ == "__main__":
    if not URL:
        print("SKIP — DATABASE_URL not set")
        sys.exit(0)
    test_load_policy_context_routes_scopes_and_expiry()
    print("PASS test_load_policy_context_routes_scopes_and_expiry")
    test_giggso_seed_is_idempotent()
    print("PASS test_giggso_seed_is_idempotent")
    print("--- policy DB integration tests passed ---")
