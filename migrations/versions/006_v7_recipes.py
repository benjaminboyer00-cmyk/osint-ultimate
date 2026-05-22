"""V7 — Recettes d'investigation partageables

Revision ID: 006_v7_recipes
Revises: 005_v6_investigation
"""
from alembic import op
import sqlalchemy as sa

revision = '006_v7_recipes'
down_revision = '005_v6_investigation'
branch_labels = None
depends_on = None


def _table_exists(name):
    insp = sa.inspect(op.get_bind())
    return name in insp.get_table_names()


def upgrade():
    if not _table_exists('recipe'):
        op.create_table(
            'recipe',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=False),
            sa.Column('name', sa.String(120), nullable=False),
            sa.Column('description', sa.Text()),
            sa.Column('target_types', sa.Text()),
            sa.Column('modules_json', sa.Text(), nullable=False),
            sa.Column('is_public', sa.Boolean(), server_default='false', nullable=False),
            sa.Column('forked_from_id', sa.Integer(), sa.ForeignKey('recipe.id'), nullable=True),
            sa.Column('usage_count', sa.Integer(), server_default='0', nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime()),
        )
        op.create_index('ix_recipe_user_id', 'recipe', ['user_id'])
        op.create_index('ix_recipe_is_public', 'recipe', ['is_public'])


def downgrade():
    if _table_exists('recipe'):
        op.drop_table('recipe')
