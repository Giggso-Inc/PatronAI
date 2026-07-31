"""remove giggso baseline — scope-first waterfall, no more guarded overrides

Revision ID: 0007_remove_giggso_baseline
Revises: 0006_raven_flagged_tools
Create Date: 2026-07-31

ADR_2026-07-31-remove-giggso-baseline-scope-priority-waterfall:

  OQ-5 (data, run FIRST): any approved_tools row with overrides_giggso=true
  or overrides_deny=true is converted to a PLAIN approve — the two flags,
  its reason, approved_by, and valid_until are all cleared. No attempt to
  preserve the override's audit metadata (simplest approach, owner-decided).

  Schema: drop giggso_baseline_deny (the global vendor-owned deny tier no
  longer exists — every org's starter deny content was seeded directly into
  its own org-scope blacklisted_tools rows by db/seeding.py at bootstrap,
  well before this migration runs). Drop the two guard CHECK constraints and
  the overrides_giggso / overrides_deny columns on approved_tools.

  OQ-4 (new): a DB-level trigger on BOTH approved_tools and blacklisted_tools
  refuses an INSERT/UPDATE that would leave the SAME
  (org_id, scope, project_id, user_id, domain-pattern) key present in the
  OPPOSITE table — belt-and-suspenders alongside the application-layer
  check in db.governance_crud._check_no_opposite_polarity. NULLs in
  project_id/user_id are compared IS NOT DISTINCT FROM (not `=`, which is
  NULL-unsafe) so an org-scope row (both NULL) still conflicts correctly
  with another org-scope row of the opposite polarity.
"""
from alembic import op
import sqlalchemy as sa

revision = "0007_remove_giggso_baseline"
down_revision = "0006_raven_flagged_tools"
branch_labels = None
depends_on = None

_GIGGSO_CK = "ck_approved_tools_giggso_override_guarded"
_DENY_OVERRIDE_CK = "ck_approved_tools_deny_override_guarded"
_FN = "fn_no_opposite_polarity"
_TRG_APPROVED = "trg_approved_tools_no_opposite_polarity"
_TRG_BLACKLISTED = "trg_blacklisted_tools_no_opposite_polarity"


def upgrade() -> None:
    # 1. OQ-5 — convert any existing override rows to plain approves BEFORE
    #    the columns that carry that state are dropped.
    op.execute("""
        UPDATE approved_tools
        SET overrides_giggso = false, overrides_deny = false,
            reason = NULL, valid_until = NULL
        WHERE overrides_giggso = true OR overrides_deny = true
    """)

    # 2. Drop the guard constraints, then the columns they guarded.
    op.execute(f"ALTER TABLE approved_tools DROP CONSTRAINT IF EXISTS {_GIGGSO_CK}")
    op.execute(f"ALTER TABLE approved_tools DROP CONSTRAINT IF EXISTS {_DENY_OVERRIDE_CK}")
    op.drop_column("approved_tools", "overrides_giggso")
    op.drop_column("approved_tools", "overrides_deny")

    # 3. Drop the global Giggso baseline table — no longer a distinct tier.
    op.drop_table("giggso_baseline_deny")

    # 4. OQ-4 — DB-level guard: same (org_id, scope, project_id, user_id,
    #    pattern) can never exist in both tables at once.
    op.execute(f"""
        CREATE OR REPLACE FUNCTION {_FN}() RETURNS trigger AS $$
        DECLARE
            conflict_pattern text;
            conflict_exists boolean;
        BEGIN
            IF TG_TABLE_NAME = 'approved_tools' THEN
                conflict_pattern := NEW.domain_pattern;
                SELECT EXISTS (
                    SELECT 1 FROM blacklisted_tools b
                    WHERE b.org_id = NEW.org_id AND b.scope = NEW.scope
                      AND b.project_id IS NOT DISTINCT FROM NEW.project_id
                      AND b.user_id IS NOT DISTINCT FROM NEW.user_id
                      AND b.domain = conflict_pattern
                ) INTO conflict_exists;
            ELSE
                conflict_pattern := NEW.domain;
                SELECT EXISTS (
                    SELECT 1 FROM approved_tools a
                    WHERE a.org_id = NEW.org_id AND a.scope = NEW.scope
                      AND a.project_id IS NOT DISTINCT FROM NEW.project_id
                      AND a.user_id IS NOT DISTINCT FROM NEW.user_id
                      AND a.domain_pattern = conflict_pattern
                ) INTO conflict_exists;
            END IF;
            IF conflict_exists THEN
                RAISE EXCEPTION
                    'OQ-4: pattern % already has an opposite-polarity row at scope % for this org/project/user',
                    conflict_pattern, NEW.scope;
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)
    op.execute(f"""
        CREATE TRIGGER {_TRG_APPROVED}
        BEFORE INSERT OR UPDATE ON approved_tools
        FOR EACH ROW EXECUTE FUNCTION {_FN}();
    """)
    op.execute(f"""
        CREATE TRIGGER {_TRG_BLACKLISTED}
        BEFORE INSERT OR UPDATE ON blacklisted_tools
        FOR EACH ROW EXECUTE FUNCTION {_FN}();
    """)


def downgrade() -> None:
    # NOTE: schema-reversible only. The OQ-5 data conversion (override rows
    # -> plain approves) is NOT reversed — that history is deliberately not
    # preserved (owner-decided "simplest approach"); downgrading restores the
    # shape, not the lost override metadata.
    op.execute(f"DROP TRIGGER IF EXISTS {_TRG_BLACKLISTED} ON blacklisted_tools")
    op.execute(f"DROP TRIGGER IF EXISTS {_TRG_APPROVED} ON approved_tools")
    op.execute(f"DROP FUNCTION IF EXISTS {_FN}()")

    op.create_table(
        "giggso_baseline_deny",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=True),
        sa.Column("category", sa.String(length=64), nullable=True),
        sa.Column("domain", sa.String(length=512), nullable=False),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("seeded_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("source", sa.String(length=64), server_default=sa.text("'config/unauthorized.csv'"), nullable=False),
        sa.CheckConstraint("severity IN ('LOW','MEDIUM','HIGH','CRITICAL')",
                           name="ck_giggso_baseline_deny_giggso_baseline_severity"),
        sa.PrimaryKeyConstraint("id", name="pk_giggso_baseline_deny"),
    )

    op.add_column("approved_tools", sa.Column(
        "overrides_giggso", sa.Boolean(), server_default=sa.text("false"), nullable=False))
    op.add_column("approved_tools", sa.Column(
        "overrides_deny", sa.Boolean(), server_default=sa.text("false"), nullable=False))
    op.execute(
        f"ALTER TABLE approved_tools ADD CONSTRAINT {_GIGGSO_CK} CHECK "
        "(overrides_giggso = false OR (reason IS NOT NULL AND approved_by IS NOT NULL "
        "AND scope IN ('org','project','user')))"
    )
    op.execute(
        f"ALTER TABLE approved_tools ADD CONSTRAINT {_DENY_OVERRIDE_CK} CHECK "
        "(overrides_deny = false OR (reason IS NOT NULL AND approved_by IS NOT NULL "
        "AND scope IN ('project','user')))"
    )
