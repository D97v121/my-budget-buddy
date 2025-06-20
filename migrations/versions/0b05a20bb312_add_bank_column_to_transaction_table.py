"""add bank column to Transaction table

Revision ID: 0b05a20bb312
Revises: 1eccdd5b83b3
Create Date: 2024-12-26 22:14:03.481122

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0b05a20bb312'
down_revision = '1eccdd5b83b3'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('transactions', schema=None) as batch_op:
        batch_op.add_column(sa.Column('bank_account', sa.String(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('transactions', schema=None) as batch_op:
        batch_op.drop_column('bank_account')

    # ### end Alembic commands ###
