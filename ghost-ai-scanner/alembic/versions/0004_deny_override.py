"""deny override — permit a wider-denied tool at a narrower scope

Revision ID: 0004_deny_override
Revises: 0003_scoped_override
Create Date: 2026-07-03

Adds approved_tools.overrides_deny (bool, default false) and a guard CHECK:
when true, the row must carry reason + approver and sit at project/user scope
(an org cannot deny-override its own org deny). org-admin-only is enforced
server-side (governance_crud), not in SQL. security_log 2026-07-03 D1-D7.
"""
from alembic import op
import sqlalchemy as sa

revision = "0004_deny_override"
down_revision = "0003_scoped_override"
branch_labels = None
depends_on = None

_CK = "ck_approved_tools_deny_override_guarded"
_DEF = ("overrides_deny = false OR (reason IS NOT NULL AND approved_by IS NOT NULL "
        "AND scope IN ('project','user'))")


def upgrade() -> None:
    op.add_column(
        "approved_tools",
        sa.Column("overrides_deny", sa.Boolean(),
                  server_default=sa.text("false"), nullable=False),
    )
    op.execute(f"ALTER TABLE approved_tools DROP CONSTRAINT IF EXISTS {_CK}")
    op.execute(f"ALTER TABLE approved_tools ADD CONSTRAINT {_CK} CHECK ({_DEF})")


def downgrade() -> None:
    op.execute(f"ALTER TABLE approved_tools DROP CONSTRAINT IF EXISTS {_CK}")
    op.drop_column("approved_tools", "overrides_deny")
