# =============================================================
# FILE: tests/integration/test_raven_enterprise_mcp_flags_db.py
# VERSION: 1.0.0
# UPDATED: 2026-07-26
# OWNER: Giggso Inc
# PURPOSE: Live-DB tests for the RavenHub -> patron MCP-governance-flag sync
#          CRUD (routers/raven_enterprise_mcp_flags.py's backing functions in
#          db.governance_crud). Requires DATABASE_URL. Self-cleaning org.
#          Same style as test_raven_enterprise_sync_db.py.
# =============================================================

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from sqlalchemy import create_engine, delete, select
from sqlalchemy.orm import Session

from db.models_identity import Org, Project, User
from db.models_policy import ApprovedTool, BlacklistedTool, RavenFlaggedTool
from db.governance_crud import (
    create_project_from_sync, create_or_touch_raven_flag, list_pending_raven_flags,
    resolve_raven_flag, get_provider_status_across_org, add_approved,
)

URL = os.environ.get("DATABASE_URL", "")
SLUG = "ztest-mcp-flags"
OTHER_SLUG = "ztest-mcp-flags-other-org"


def _run():
    eng = create_engine(URL, future=True)
    with Session(eng) as s:
        s.execute(delete(Org).where(Org.slug.in_([SLUG, OTHER_SLUG]))); s.commit()
        org = Org(slug=SLUG, display_name="Z", s3_bucket="b")
        other_org = Org(slug=OTHER_SLUG, display_name="Z2", s3_bucket="b2")
        s.add_all([org, other_org]); s.flush()
        try:
            project = create_project_from_sync(
                s, org_id=org.id, slug="eng", display_name="Engineering",
                external_source="ravenhub", external_ref="group-mcp-1",
            )
            other_project = create_project_from_sync(
                s, org_id=other_org.id, slug="eng", display_name="Engineering (other org)",
                external_source="ravenhub", external_ref="group-mcp-other",
            )

            # 1. Create a new pending flag.
            flag = create_or_touch_raven_flag(
                s, org_id=org.id, project_id=project.id, provider_pattern="Gmail",
                requested_by="owner@raven.test", note="requested by project owner X",
            )
            assert flag.status == "pending"
            assert flag.provider_pattern == "gmail"   # lowercased, matches ApprovedTool/BlacklistedTool convention

            # 2. Idempotent retry: same (project, provider) while pending ->
            #    updates the existing row, does NOT create a duplicate.
            retried = create_or_touch_raven_flag(
                s, org_id=org.id, project_id=project.id, provider_pattern="gmail",
                requested_by="owner@raven.test", note="updated note",
            )
            assert retried.id == flag.id
            assert retried.note == "updated note"
            count = s.query(RavenFlaggedTool).filter_by(project_id=project.id, provider_pattern="gmail").count()
            assert count == 1, f"expected exactly 1 row, got {count}"

            # 3. A different provider on the same project creates a separate row.
            other_flag = create_or_touch_raven_flag(
                s, org_id=org.id, project_id=project.id, provider_pattern="filesystem",
                requested_by="owner@raven.test", note=None,
            )
            assert other_flag.id != flag.id

            # 4. list_pending_raven_flags is scoped by org and (optionally) project.
            pending = list_pending_raven_flags(s, org_id=org.id)
            assert {f.provider_pattern for f in pending} == {"gmail", "filesystem"}
            pending_scoped = list_pending_raven_flags(s, org_id=org.id, project_id=project.id)
            assert len(pending_scoped) == 2

            # 5. Org isolation: a flag in a different org must not leak into this org's list.
            create_or_touch_raven_flag(
                s, org_id=other_org.id, project_id=other_project.id, provider_pattern="gmail",
                requested_by="owner2@raven.test", note=None,
            )
            assert {f.provider_pattern for f in list_pending_raven_flags(s, org_id=org.id)} == {"gmail", "filesystem"}

            # 6. Manually resolving a flag (simulating Phase 3's UI action) then
            #    re-touching the same (project, provider) creates a FRESH pending
            #    row — a past decision doesn't silently swallow a new request.
            flag.status = "approved"
            s.commit()
            fresh = create_or_touch_raven_flag(
                s, org_id=org.id, project_id=project.id, provider_pattern="gmail",
                requested_by="owner@raven.test", note="asked again",
            )
            assert fresh.id != flag.id
            assert fresh.status == "pending"

            # 7. resolve_raven_flag(approve=True) writes a REAL ApprovedTool row
            #    at project scope and marks the flag resolved (Phase 3). The
            #    stored domain_pattern is WRAPPED as "mcp:*:<name>" — patron's
            #    own scanner reports MCP servers as "mcp:<host>:<name>"
            #    (agent_explode.py's _provider_for), never the bare raven
            #    name, so an unwrapped pattern would never match anything
            #    patron later scans for that same MCP server.
            admin = User(org_id=org.id, email="admin@zt-mcp.com", is_org_admin=True)
            s.add(admin); s.flush()
            resolved = resolve_raven_flag(
                s, actor=admin, org_id=org.id, project_id=project.id,
                flag_id=other_flag.id, approve=True,
            )
            assert resolved is not None and resolved.status == "approved"
            approved_row = s.execute(
                select(ApprovedTool).where(
                    ApprovedTool.project_id == project.id, ApprovedTool.domain_pattern == "mcp:*:filesystem",
                )
            ).scalars().first()
            assert approved_row is not None
            assert approved_row.name == "filesystem"   # display name stays the raw raven mcp_name
            assert "RavenHub" in (approved_row.reason or "")
            # Confirms the wrapped pattern actually matches what patron's own
            # scanner would report for the same MCP server, on any host.
            from scoring.policy import _matches
            assert _matches("mcp:claude_desktop:filesystem", {approved_row.domain_pattern})
            assert not _matches("filesystem", {approved_row.domain_pattern})   # bare name must NOT match

            # 8. resolve_raven_flag(approve=False) writes a BlacklistedTool row instead.
            deny_flag = create_or_touch_raven_flag(
                s, org_id=org.id, project_id=project.id, provider_pattern="shodan",
                requested_by="owner@raven.test", note=None,
            )
            denied = resolve_raven_flag(
                s, actor=admin, org_id=org.id, project_id=project.id,
                flag_id=deny_flag.id, approve=False,
            )
            assert denied.status == "denied"
            denied_row = s.execute(
                select(BlacklistedTool).where(
                    BlacklistedTool.project_id == project.id, BlacklistedTool.domain == "mcp:*:shodan",
                )
            ).scalars().first()
            assert denied_row is not None
            assert denied_row.name == "shodan"

            # 9. Resolving an already-resolved (or nonexistent) flag returns None
            #    — a no-op, never a crash or a double-write.
            assert resolve_raven_flag(
                s, actor=admin, org_id=org.id, project_id=project.id,
                flag_id=resolved.id, approve=True,
            ) is None

            # 10. get_provider_status_across_org (Phase 4 cross-project awareness):
            #     the two project-scope decisions above surface with the
            #     project's raven external_ref, and a fresh org-scope approve
            #     shows up as org_approved=True.
            status_fs = get_provider_status_across_org(s, org_id=org.id, provider_pattern="filesystem")
            assert status_fs["projects"] == [{"external_ref": "group-mcp-1", "status": "approved"}]
            assert status_fs["org_approved"] is False

            status_shodan = get_provider_status_across_org(s, org_id=org.id, provider_pattern="shodan")
            assert status_shodan["projects"] == [{"external_ref": "group-mcp-1", "status": "denied"}]

            # Org-scope raven approval doesn't have a resolve_raven_flag path yet
            # (project scope only) — write the wrapped pattern directly to
            # simulate one and confirm the lookup key shape matches.
            add_approved(s, actor=admin, org_id=org.id, scope="org", name="slack",
                        provider_pattern="mcp:*:slack")
            status_slack = get_provider_status_across_org(s, org_id=org.id, provider_pattern="slack")
            assert status_slack["org_approved"] is True
            assert status_slack["projects"] == []

            # An UNWRAPPED, patron-native org approval (e.g. a real domain a
            # patron admin typed through the normal UI, unrelated to any raven
            # MCP) must NOT be misreported as a raven-MCP decision.
            add_approved(s, actor=admin, org_id=org.id, scope="org", name="Slack Web",
                        provider_pattern="slack.com")
            status_slack_com = get_provider_status_across_org(s, org_id=org.id, provider_pattern="slack.com")
            assert status_slack_com["org_approved"] is False

            # Cross-org isolation: the other org's flags/decisions never leak in.
            status_other_org = get_provider_status_across_org(s, org_id=other_org.id, provider_pattern="filesystem")
            assert status_other_org == {"provider_pattern": "filesystem", "org_approved": False,
                                        "org_denied": False, "projects": []}

            print("PASS raven_enterprise mcp-flags CRUD (idempotent create+touch, "
                  "distinct-provider separation, org-scoped listing, org isolation, "
                  "fresh-pending-after-resolve, resolve-to-approved, resolve-to-denied "
                  "with mcp:*: pattern wrapping verified against real patron-scan-shaped "
                  "strings, double-resolve no-op, cross-project status (project+org scope, "
                  "wrapped-vs-unwrapped isolation, cross-org isolation) — 11 checks)")
        finally:
            s.execute(delete(ApprovedTool).where(ApprovedTool.org_id.in_([org.id, other_org.id])))
            s.execute(delete(BlacklistedTool).where(BlacklistedTool.org_id.in_([org.id, other_org.id])))
            s.execute(delete(RavenFlaggedTool).where(RavenFlaggedTool.org_id.in_([org.id, other_org.id])))
            s.execute(delete(User).where(User.org_id == org.id))
            s.execute(delete(Project).where(Project.org_id.in_([org.id, other_org.id])))
            s.execute(delete(Org).where(Org.slug.in_([SLUG, OTHER_SLUG])))
            s.commit()


if __name__ == "__main__":
    if not URL:
        print("SKIP — DATABASE_URL not set"); sys.exit(0)
    _run()
    print("--- raven_enterprise mcp-flags CRUD integration test passed ---")
