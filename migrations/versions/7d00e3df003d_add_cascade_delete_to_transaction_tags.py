"""Add cascade delete to transaction_tags

Revision ID: 7d00e3df003d
Revises: 65dee00451a9
Create Date: 2025-01-06 21:28:41.073050

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7d00e3df003d'
down_revision = '65dee00451a9'
branch_labels = None
depends_on = None


def upgrade():
    # Drop and recreate the transaction_tags table with cascade delete
    op.drop_table('transaction_tags')
    op.create_table(
        'transaction_tags',
        sa.Column('transaction_id', sa.Integer, sa.ForeignKey('transaction.id', ondelete="CASCADE"), primary_key=True),
        sa.Column('tag_id', sa.Integer, sa.ForeignKey('tags.id', ondelete="CASCADE"), primary_key=True)
    )

def downgrade():
    # Drop and recreate the transaction_tags table without cascade delete
    op.drop_table('transaction_tags')
    op.create_table(
        'transaction_tags',
        sa.Column('transaction_id', sa.Integer, sa.ForeignKey('transaction.id'), primary_key=True),
        sa.Column('tag_id', sa.Integer, sa.ForeignKey('tags.id'), primary_key=True)
    )


    # ### end Alembic commands ###
