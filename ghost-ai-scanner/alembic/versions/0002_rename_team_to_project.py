"""rename team -> project (tables, columns, scope, constraints)

Revision ID: 0002_team_to_project
Revises: 0b106c6c7a43
Create Date: 2026-07-01

Renames the team concept to project across the policy DB, preserving all
existing rows. teams->projects, team_members->project_members,
team_id->project_id, is_team_admin->is_project_admin, scope 'team'->'project'.
"""
from alembic import op

revision = "0002_team_to_project"
down_revision = "0b106c6c7a43"
branch_labels = None
depends_on = None

_APPROVED_CK = "ck_approved_tools_approved_scope"
_BLACKLIST_CK = "ck_blacklisted_tools_blacklisted_scope"


def upgrade() -> None:
    # -- tables --
    op.execute("ALTER TABLE teams RENAME TO projects")
    op.execute("ALTER TABLE team_members RENAME TO project_members")
    # -- columns --
    op.execute("ALTER TABLE project_members RENAME COLUMN team_id TO project_id")
    op.execute("ALTER TABLE project_members RENAME COLUMN is_team_admin TO is_project_admin")
    op.execute("ALTER TABLE approved_tools RENAME COLUMN team_id TO project_id")
    op.execute("ALTER TABLE blacklisted_tools RENAME COLUMN team_id TO project_id")
    # -- drop the old scope CHECKs FIRST (they only allow 'team'), so the
    #    UPDATE to 'project' doesn't violate them, then re-add allowing 'project'.
    op.execute(f"ALTER TABLE approved_tools DROP CONSTRAINT IF EXISTS {_APPROVED_CK}")
    op.execute(f"ALTER TABLE blacklisted_tools DROP CONSTRAINT IF EXISTS {_BLACKLIST_CK}")
    op.execute("UPDATE approved_tools SET scope='project' WHERE scope='team'")
    op.execute("UPDATE blacklisted_tools SET scope='project' WHERE scope='team'")
    op.execute(f"ALTER TABLE approved_tools ADD CONSTRAINT {_APPROVED_CK} "
               "CHECK (scope IN ('org','project','user'))")
    op.execute(f"ALTER TABLE blacklisted_tools ADD CONSTRAINT {_BLACKLIST_CK} "
               "CHECK (scope IN ('org','project','user'))")
    # -- indexes (cosmetic rename to match the models) --
    op.execute("ALTER INDEX IF EXISTS ix_approved_tools_team RENAME TO ix_approved_tools_project")


def downgrade() -> None:
    op.execute("ALTER INDEX IF EXISTS ix_approved_tools_project RENAME TO ix_approved_tools_team")
    op.execute(f"ALTER TABLE blacklisted_tools DROP CONSTRAINT IF EXISTS {_BLACKLIST_CK}")
    op.execute(f"ALTER TABLE blacklisted_tools ADD CONSTRAINT {_BLACKLIST_CK} "
               "CHECK (scope IN ('org','team','user'))")
    op.execute(f"ALTER TABLE approved_tools DROP CONSTRAINT IF EXISTS {_APPROVED_CK}")
    op.execute(f"ALTER TABLE approved_tools ADD CONSTRAINT {_APPROVED_CK} "
               "CHECK (scope IN ('org','team','user'))")
    op.execute("UPDATE approved_tools SET scope='team' WHERE scope='project'")
    op.execute("UPDATE blacklisted_tools SET scope='team' WHERE scope='project'")
    op.execute("ALTER TABLE blacklisted_tools RENAME COLUMN project_id TO team_id")
    op.execute("ALTER TABLE approved_tools RENAME COLUMN project_id TO team_id")
    op.execute("ALTER TABLE project_members RENAME COLUMN is_project_admin TO is_team_admin")
    op.execute("ALTER TABLE project_members RENAME COLUMN project_id TO team_id")
    op.execute("ALTER TABLE project_members RENAME TO team_members")
    op.execute("ALTER TABLE projects RENAME TO teams")
