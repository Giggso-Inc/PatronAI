"""unified identity link columns

Adds nullable ADR-001 canonical identity links and the shared 5-role value.
The existing PatronAI orgs/users tables remain in place for compatibility
until the final identity cutover.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "0007_unified_identity_links"
down_revision = "0006_raven_flagged_tools"
branch_labels = None
depends_on = None

_ROLE_CK = "ck_users_role_canonical"


def upgrade() -> None:
    op.add_column("orgs", sa.Column("identity_org_id", UUID(as_uuid=True), nullable=True))
    op.create_index("ix_orgs_identity_org_id", "orgs", ["identity_org_id"], unique=True)
    op.create_foreign_key(
        "fk_orgs_identity_org",
        "orgs",
        "orgs",
        ["identity_org_id"],
        ["id"],
        referent_schema="identity",
        ondelete="RESTRICT",
    )

    op.add_column("users", sa.Column("identity_user_id", UUID(as_uuid=True), nullable=True))
    op.add_column(
        "users",
        sa.Column("role", sa.String(length=32), nullable=False, server_default="VIEWER"),
    )
    op.execute("UPDATE users SET role='ORG_ADMIN' WHERE is_org_admin IS TRUE")
    op.create_index("ix_users_identity_user_id", "users", ["identity_user_id"], unique=True)
    op.create_foreign_key(
        "fk_users_identity_user",
        "users",
        "users",
        ["identity_user_id"],
        ["id"],
        referent_schema="identity",
        ondelete="SET NULL",
    )
    op.execute(
        f"ALTER TABLE users ADD CONSTRAINT {_ROLE_CK} "
        "CHECK (role IN ('ORG_ADMIN','SECURITY_ADMIN','ENGINEERING_ADMIN','PROJECT_ADMIN','VIEWER'))"
    )


def downgrade() -> None:
    op.execute(f"ALTER TABLE users DROP CONSTRAINT IF EXISTS {_ROLE_CK}")
    op.drop_constraint("fk_users_identity_user", "users", type_="foreignkey")
    op.drop_index("ix_users_identity_user_id", table_name="users")
    op.drop_column("users", "role")
    op.drop_column("users", "identity_user_id")

    op.drop_constraint("fk_orgs_identity_org", "orgs", type_="foreignkey")
    op.drop_index("ix_orgs_identity_org_id", table_name="orgs")
    op.drop_column("orgs", "identity_org_id")
