"""Add scan_mode and company_profile_json to scans

Revision ID: 0002
Revises: 0001
Create Date: 2024-01-02 00:00:00
"""
from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("scan_mode", sa.String(32), nullable=False, server_default="pentest"),
    )
    op.add_column(
        "scans",
        sa.Column("company_profile_json", sa.Text(), nullable=True, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_column("scans", "company_profile_json")
    op.drop_column("scans", "scan_mode")
