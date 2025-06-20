"""Add tag column to transaction model

Revision ID: f355b2ef71dd
Revises: 95716aa7377f
Create Date: 2024-12-26 16:16:49.267819

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f355b2ef71dd'
down_revision = '95716aa7377f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('transactions', schema=None) as batch_op:
        batch_op.add_column(sa.Column('tag_name', sa.String(length=50), nullable=False, server_default='None'))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('transactions', schema=None) as batch_op:
        batch_op.drop_column('tag_name')

    # ### end Alembic commands ###
