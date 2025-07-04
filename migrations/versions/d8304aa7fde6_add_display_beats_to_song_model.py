"""Add display_beats to Song model

Revision ID: d8304aa7fde6
Revises: 0ee0f347e43a
Create Date: 2025-06-02 11:01:32.944691

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd8304aa7fde6'
down_revision = '0ee0f347e43a'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('song', schema=None) as batch_op:
        batch_op.add_column(sa.Column('display_beats', sa.Integer(), server_default='4', nullable=False))

    op.create_table(
        'site_option',
        sa.Column('key', sa.String(length=64), primary_key=True),
        sa.Column('value', sa.String(length=256), nullable=False)
    )

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('song', schema=None) as batch_op:
        batch_op.drop_column('display_beats')

    op.drop_table('site_option')

    # ### end Alembic commands ###
