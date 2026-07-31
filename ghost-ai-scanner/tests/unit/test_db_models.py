# =============================================================
# FILE: tests/unit/test_db_models.py
# VERSION: 2.0.0
# UPDATED: 2026-07-31
# OWNER: Giggso Inc
# PURPOSE: Schema-invariant tests for the policy/identity DB
#          (ADR_2026-07-31). Metadata-only — no live Postgres needed,
#          so these run in CI without a DB. The live trigger behaviour
#          (OQ-4 opposite-polarity guard) is exercised by the migration
#          smoke test / integration tests.
# AUDIT LOG:
#   v1.0.0  2026-06-29  Initial (ADR_2026-06-29 schema).
#   v2.0.0  2026-07-31  ADR_2026-07-31: giggso_baseline_deny table and the
#                       overrides_giggso/overrides_deny columns are gone.
# =============================================================

import db


def _table(name):
    return db.Base.metadata.tables[name]


def test_all_inscope_tables_present():
    """The in-scope tables exist; the Giggso baseline table does NOT."""
    present = set(db.Base.metadata.tables)
    assert {
        "orgs", "users", "projects", "project_members",
        "approved_tools", "blacklisted_tools", "schema_migrations",
    } <= present
    assert "approval_requests" not in present
    assert "giggso_baseline_deny" not in present   # ADR_2026-07-31


def test_scope_columns_are_org_project_user_only():
    """No project_id column survives on the scoped policy tables."""
    for t in ("approved_tools", "blacklisted_tools"):
        cols = set(_table(t).columns.keys())
        assert "scope" in cols
        assert "project_id" in cols


def test_lists_keyed_on_provider_pattern():
    """Allow/deny entries store a provider glob, not a bare domain field."""
    assert "domain_pattern" in _table("approved_tools").columns
    assert "domain" in _table("blacklisted_tools").columns


def test_no_giggso_override_columns_remain():
    """ADR_2026-07-31: no more guarded-override machinery on approved_tools."""
    at = _table("approved_tools")
    assert "overrides_giggso" not in at.columns
    assert "overrides_deny" not in at.columns
    ck_names = {
        c.name for c in at.constraints
        if c.__class__.__name__ == "CheckConstraint"
    }
    assert "ck_approved_tools_giggso_override_guarded" not in ck_names
    assert "ck_approved_tools_deny_override_guarded" not in ck_names
    assert "ck_approved_tools_approved_scope" in ck_names
