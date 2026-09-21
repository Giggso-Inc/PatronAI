"""raven_flagged_tools: add device_count

Revision ID: 0008_device_count
Revises: 0007_remove_giggso_baseline
Create Date: 2026-09-18

Distinct users calling the flagged MCP in the raven project it was
forwarded from — raven computes this at forward time
(hub/app/services/mcp_asset_inventory.py::mcp_member_count) and sends it as
device_count in the POST /raven-enterprise/mcp-flags/sync body. Nullable-safe
default of 0 so existing rows (forwarded before this column existed) render
as 0, not null.

Revision id kept <=32 chars: alembic_version.version_num is VARCHAR(32) by
default, and the original id (0008_raven_flagged_tools_device_count, 38
chars) overflowed it — StringDataRightTruncation on every environment,
never actually applied anywhere, so safe to rename without a data migration.
"""
from alembic import op
import sqlalchemy as sa

revision = "0008_device_count"
down_revision = "0007_remove_giggso_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "raven_flagged_tools",
        sa.Column("device_count", sa.Integer(), server_default=sa.text("0"), nullable=False),
    )


def downgrade() -> None:
    op.drop_column("raven_flagged_tools", "device_count")
