# =============================================================
# FILE: tests/unit/test_ravenhub_projects.py
# VERSION: 1.0.0
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
# =============================================================

import contextlib
import sys
from pathlib import Path
from types import SimpleNamespace

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
