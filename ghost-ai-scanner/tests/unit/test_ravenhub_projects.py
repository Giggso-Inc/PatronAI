# =============================================================
# FILE: tests/unit/test_ravenhub_projects.py
# VERSION: 1.1.0
# UPDATED: 2026-08-24
# OWNER: Giggso Inc
# PURPOSE: Lock routers/ravenhub_projects.py's list_projects_endpoint —
#          specifically that it only returns Patron projects synced FROM
#          RavenHub (external_source == "ravenhub"), filtering out projects
#          created directly in Patron itself (e.g. demo/test data with no
#          external_source). Regression coverage for the "Grant project
#          exception" picker showing phantom projects RavenHub never
#          created (GSD ticket, 2026-08-24). Pure; no real DB — everything
#          is stubbed.
# AUDIT LOG:
#   v1.0.0  2026-08-24  Initial — list-filter coverage.
#   v1.1.0  2026-08-24  PR review (C1): create_project_endpoint didn't stamp
#                       external_source, so a project created through this
#                       router was immediately invisible in its own list.
#                       Added a create-then-list round-trip test plus a
#                       direct create_project() call-arg check. (M1) the
#                       three member-management endpoints must 404 for a
#                       non-ravenhub project the same way the list filters
#                       it out, not silently operate on it anyway.
# =============================================================

import contextlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT))

import routers.ravenhub_projects as ravenhub_projects


def _project(display_name, slug, external_source=None):
    return SimpleNamespace(
        id="00000000-0000-0000-0000-000000000001",
        slug=slug, display_name=display_name, external_source=external_source,
    )


def test_list_projects_endpoint_filters_out_non_ravenhub_projects(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://fake")
    monkeypatch.setattr(
        ravenhub_projects, "_resolve_actor",
        lambda s, email: (SimpleNamespace(id="actor-1"), "org-1"),
    )

    rows = [
        (_project("BuildAndBreak", "buildandbreak", "ravenhub"), 2),
        (_project("GSD (Giggso Security Domain)", "gsd-giggso-security-domain", "ravenhub"), 6),
        (_project("Sample-GSD", "gsd_sample", None), 0),
        (_project("Sample GSD 2", "engineer", None), 0),
    ]

    import db.engine as engine_mod
    import db.governance_crud as crud_mod
    monkeypatch.setattr(engine_mod, "get_session", lambda: contextlib.nullcontext(object()))
    monkeypatch.setattr(crud_mod, "list_projects", lambda s, org_id: rows)

    result = ravenhub_projects.list_projects_endpoint(email="admin@giggso.com")

    slugs = {p.slug for p in result.projects}
    assert slugs == {"buildandbreak", "gsd-giggso-security-domain"}
    assert "gsd_sample" not in slugs and "engineer" not in slugs


def test_list_projects_endpoint_empty_when_none_are_ravenhub_sourced(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://fake")
    monkeypatch.setattr(
        ravenhub_projects, "_resolve_actor",
        lambda s, email: (SimpleNamespace(id="actor-1"), "org-1"),
    )

    rows = [(_project("Sample-GSD", "gsd_sample", None), 0)]

    import db.engine as engine_mod
    import db.governance_crud as crud_mod
    monkeypatch.setattr(engine_mod, "get_session", lambda: contextlib.nullcontext(object()))
    monkeypatch.setattr(crud_mod, "list_projects", lambda s, org_id: rows)

    result = ravenhub_projects.list_projects_endpoint(email="admin@giggso.com")
    assert result.projects == []


def test_create_project_endpoint_stamps_external_source_ravenhub(monkeypatch):
    """C1: this router only ever serves RavenHub — a project it creates
    must be stamped the same way a synced one is, or it vanishes from this
    same router's own filtered list right after being created."""
    monkeypatch.setenv("DATABASE_URL", "postgresql://fake")
    monkeypatch.setattr(
        ravenhub_projects, "_resolve_actor",
        lambda s, email: (SimpleNamespace(id="actor-1", is_org_admin=True), "org-1"),
    )

    calls = []

    def fake_create_project(s, **kwargs):
        calls.append(kwargs)
        return _project(kwargs["display_name"], kwargs["slug"], kwargs.get("external_source"))

    import db.engine as engine_mod
    import db.governance_crud as crud_mod
    monkeypatch.setattr(engine_mod, "get_session", lambda: contextlib.nullcontext(object()))
    monkeypatch.setattr(crud_mod, "create_project", fake_create_project)

    ravenhub_projects.create_project_endpoint(
        ravenhub_projects.CreateProjectRequest(slug="new-svc", display_name="New Service"),
        email="admin@giggso.com",
    )

    assert calls[0]["external_source"] == "ravenhub"


def test_create_then_list_round_trip_shows_the_new_project(monkeypatch):
    """The exact regression from C1: before the fix, this create-then-list
    sequence — a previously-working flow — went from passing to silently
    failing (the new project 200s on create, then simply isn't in the very
    list it was just created through)."""
    monkeypatch.setenv("DATABASE_URL", "postgresql://fake")
    monkeypatch.setattr(
        ravenhub_projects, "_resolve_actor",
        lambda s, email: (SimpleNamespace(id="actor-1", is_org_admin=True), "org-1"),
    )

    fake_db = []

    def fake_create_project(s, **kwargs):
        row = _project(kwargs["display_name"], kwargs["slug"], kwargs.get("external_source"))
        fake_db.append(row)
        return row

    def fake_list_projects(s, org_id):
        return [(row, 0) for row in fake_db]

    import db.engine as engine_mod
    import db.governance_crud as crud_mod
    monkeypatch.setattr(engine_mod, "get_session", lambda: contextlib.nullcontext(object()))
    monkeypatch.setattr(crud_mod, "create_project", fake_create_project)
    monkeypatch.setattr(crud_mod, "list_projects", fake_list_projects)

    ravenhub_projects.create_project_endpoint(
        ravenhub_projects.CreateProjectRequest(slug="new-svc", display_name="New Service"),
        email="admin@giggso.com",
    )
    result = ravenhub_projects.list_projects_endpoint(email="admin@giggso.com")

    assert [p.slug for p in result.projects] == ["new-svc"]


# ── M1: member-management endpoints must not operate on a non-ravenhub project ──

def _setup_common(monkeypatch, external_source):
    monkeypatch.setenv("DATABASE_URL", "postgresql://fake")
    monkeypatch.setattr(
        ravenhub_projects, "_resolve_actor",
        lambda s, email: (SimpleNamespace(id="actor-1", is_org_admin=True), "org-1"),
    )
    import db.engine as engine_mod
    import db.governance_crud as crud_mod
    monkeypatch.setattr(engine_mod, "get_session", lambda: contextlib.nullcontext(object()))
    monkeypatch.setattr(crud_mod, "check_target_in_org", lambda s, **kw: None)
    monkeypatch.setattr(
        crud_mod, "resolve_project_in_org",
        lambda s, org_id, project_id: _project("Some Project", project_id, external_source),
    )
    return crud_mod


def test_list_members_404s_for_a_non_ravenhub_project(monkeypatch):
    _setup_common(monkeypatch, external_source=None)
    with pytest.raises(HTTPException) as exc:
        ravenhub_projects.list_project_members_endpoint(project_id="gsd_sample", email="admin@giggso.com")
    assert exc.value.status_code == 404


def test_add_member_404s_for_a_non_ravenhub_project(monkeypatch):
    crud_mod = _setup_common(monkeypatch, external_source=None)
    calls = []
    monkeypatch.setattr(crud_mod, "add_project_member", lambda **kw: calls.append(kw))
    with pytest.raises(HTTPException) as exc:
        ravenhub_projects.add_project_member_endpoint(
            project_id="gsd_sample", body=ravenhub_projects.AddMemberRequest(user_id="u-1"),
            email="admin@giggso.com",
        )
    assert exc.value.status_code == 404
    assert calls == []  # never reached the actual mutation


def test_remove_member_404s_for_a_non_ravenhub_project(monkeypatch):
    crud_mod = _setup_common(monkeypatch, external_source=None)
    calls = []
    monkeypatch.setattr(crud_mod, "remove_project_member", lambda **kw: calls.append(kw))
    with pytest.raises(HTTPException) as exc:
        ravenhub_projects.remove_project_member_endpoint(
            project_id="gsd_sample", user_id="u-1", email="admin@giggso.com",
        )
    assert exc.value.status_code == 404
    assert calls == []


def test_list_members_succeeds_for_a_ravenhub_project(monkeypatch):
    crud_mod = _setup_common(monkeypatch, external_source="ravenhub")
    monkeypatch.setattr(crud_mod, "list_project_members", lambda s, project_id: [])
    monkeypatch.setattr(crud_mod, "list_org_users", lambda s, org_id: [])
    result = ravenhub_projects.list_project_members_endpoint(project_id="buildandbreak", email="admin@giggso.com")
    assert result.members == []


def test_require_ravenhub_project_converts_policy_authz_error_to_404(monkeypatch):
    """N1 (2026-08-24 review round 2): every real call site already calls
    check_target_in_org() for this exact project_id first, so
    resolve_project_in_org() can't newly raise PolicyAuthzError in
    practice — but that's a calling convention, not a structural
    guarantee. Calling _require_ravenhub_project directly, bypassing that
    precondition entirely, must still 404 cleanly rather than let a bare
    PolicyAuthzError escape as an unhandled 500 (no global handler for it
    exists anywhere in this app)."""
    import db.governance_crud as crud_mod

    def _raise(s, org_id, project_id):
        raise crud_mod.PolicyAuthzError("project_id not found in this org")
    monkeypatch.setattr(crud_mod, "resolve_project_in_org", _raise)

    with pytest.raises(HTTPException) as exc:
        ravenhub_projects._require_ravenhub_project(object(), "org-1", "not-a-real-project")
    assert exc.value.status_code == 404
