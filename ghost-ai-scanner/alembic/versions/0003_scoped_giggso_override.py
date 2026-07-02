"""scoped giggso override — allow project/user override scope

Revision ID: 0003_scoped_override
Revises: 0002_team_to_project
Create Date: 2026-07-01

Relaxes the giggso-override guard CHECK so an override may be granted at
org / project / user scope (was org-only). reason + approver still required;
org-admin-only is enforced server-side (governance_crud), not in SQL.
"""
from alembic import op

revision = "0003_scoped_override"
down_revision = "0002_team_to_project"
branch_labels = None
depends_on = None

_CK = "ck_approved_tools_giggso_override_guarded"
_NEW = ("overrides_giggso = false OR (reason IS NOT NULL AND approved_by IS NOT NULL "
        "AND scope IN ('org','project','user'))")
_OLD = ("overrides_giggso = false OR (reason IS NOT NULL AND approved_by IS NOT NULL "
        "AND scope = 'org')")


def upgrade() -> None:
    op.execute(f"ALTER TABLE approved_tools DROP CONSTRAINT IF EXISTS {_CK}")
    op.execute(f"ALTER TABLE approved_tools ADD CONSTRAINT {_CK} CHECK ({_NEW})")


def downgrade() -> None:
    op.execute(f"ALTER TABLE approved_tools DROP CONSTRAINT IF EXISTS {_CK}")
    op.execute(f"ALTER TABLE approved_tools ADD CONSTRAINT {_CK} CHECK ({_OLD})")
