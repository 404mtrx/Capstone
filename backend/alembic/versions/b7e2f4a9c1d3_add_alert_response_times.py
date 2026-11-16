"""add alert acknowledged_at and closed_at

Revision ID: b7e2f4a9c1d3
Revises: a4c1d2e3f5b6
Create Date: 2026-11-10 17:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'b7e2f4a9c1d3'
down_revision: Union[str, Sequence[str], None] = 'a4c1d2e3f5b6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('alert', sa.Column('acknowledged_at', sqlmodel.sql.sqltypes.UTCDateTime(), nullable=True))
    op.add_column('alert', sa.Column('closed_at', sqlmodel.sql.sqltypes.UTCDateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column('alert', 'closed_at')
    op.drop_column('alert', 'acknowledged_at')
