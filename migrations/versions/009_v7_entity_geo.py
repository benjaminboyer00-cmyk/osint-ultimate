"""V7 Phase 5 — Coordonnées géographiques sur les entités

Revision ID: 009_v7_entity_geo
Revises: 008_v7_report_seal
"""
from alembic import op
import sqlalchemy as sa

revision = '009_v7_entity_geo'
down_revision = '008_v7_report_seal'
branch_labels = None
depends_on = None


def _col_exists(table, col):
    insp = sa.inspect(op.get_bind())
    if table not in insp.get_table_names():
        return False
    return col in [c['name'] for c in insp.get_columns(table)]


def upgrade():
    if not _col_exists('entity', 'latitude'):
        op.add_column('entity', sa.Column('latitude', sa.Float(), nullable=True))
    if not _col_exists('entity', 'longitude'):
        op.add_column('entity', sa.Column('longitude', sa.Float(), nullable=True))
    if not _col_exists('entity', 'geo_label'):
        op.add_column('entity', sa.Column('geo_label', sa.String(255), nullable=True))
    if not _col_exists('entity', 'geo_source'):
        op.add_column('entity', sa.Column('geo_source', sa.String(50), nullable=True))


def downgrade():
    for col in ('geo_source', 'geo_label', 'longitude', 'latitude'):
        if _col_exists('entity', col):
            op.drop_column('entity', col)
