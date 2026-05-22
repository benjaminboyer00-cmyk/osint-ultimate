"""V8 — Préférence scrape fallback utilisateur

Revision ID: 007_v8_scrape_pref
Revises: 006_v7_recipes
"""
from alembic import op
import sqlalchemy as sa

revision = '007_v8_scrape_pref'
down_revision = '006_v7_recipes'
branch_labels = None
depends_on = None


def _col_exists(table, col):
    insp = sa.inspect(op.get_bind())
    if table not in insp.get_table_names():
        return False
    return col in [c['name'] for c in insp.get_columns(table)]


def upgrade():
    if not _col_exists('user', 'scrape_fallback_enabled'):
        op.add_column(
            'user',
            sa.Column('scrape_fallback_enabled', sa.Boolean(), server_default='true', nullable=False),
        )


def downgrade():
    if _col_exists('user', 'scrape_fallback_enabled'):
        op.drop_column('user', 'scrape_fallback_enabled')
