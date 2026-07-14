# =============================================================
# FILE: tests/unit/test_db_models.py
# VERSION: 1.0.0
# UPDATED: 2026-06-29
# OWNER: Giggso Inc
# PURPOSE: Schema-invariant tests for the policy/identity DB
#          (ADR_2026-06-29). Metadata-only — no live Postgres needed,
#          so these run in CI without a DB. The live CHECK behaviour
#          (override guard) is exercised by the migration smoke test.
# =============================================================

import db


def _table(name):
    return db.Base.metadata.tables[name]


def test_all_inscope_tables_present():
    """The 8 ADR-frozen tables exist; dropped tables do NOT."""
    present = set(db.Base.metadata.tables)
    assert {
        "orgs", "users", "projects", "project_members",
        "approved_tools", "blacklisted_tools",
        "giggso_baseline_deny", "schema_migrations",
    } <= present
    # Project scope + approval workflow were dropped in the amendment.
    # projects/project_members ARE the renamed team tables (in scope now);
    # only the approval workflow stays dropped.
    assert "approval_requests" not in present


def test_scope_columns_are_org_project_user_only():
    """No project_id column survives on the scoped policy tables."""
    for t in ("approved_tools", "blacklisted_tools"):
        cols = set(_table(t).columns.keys())
        assert "scope" in cols
        assert "project_id" in cols   # project scope column (renamed from team_id)


def test_lists_keyed_on_provider_pattern():
    """Allow/deny entries store a provider glob, not a bare domain field."""
    assert "domain_pattern" in _table("approved_tools").columns
    assert "domain" in _table("blacklisted_tools").columns
    assert "domain" in _table("giggso_baseline_deny").columns


def test_giggso_override_column_and_guard():
    """overrides_giggso exists and is protected by a CHECK (condition C1)."""
    at = _table("approved_tools")
    assert "overrides_giggso" in at.columns
    ck_names = {
        c.name for c in at.constraints
        if c.__class__.__name__ == "CheckConstraint"
    }
    assert "ck_approved_tools_giggso_override_guarded" in ck_names
    assert "ck_approved_tools_approved_scope" in ck_names


def test_giggso_baseline_is_standalone():
    """Baseline mirror carries a source marker and is not user-scoped."""
    g = _table("giggso_baseline_deny")
    assert "source" in g.columns
    assert "scope" not in g.columns  # baseline is global, not scoped
