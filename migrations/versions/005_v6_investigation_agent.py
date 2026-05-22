"""V6 — Agent enquête guidée + scoring liens

Revision ID: 005_v6_investigation
Revises: 004_v5_platform
"""
from alembic import op
import sqlalchemy as sa

revision = '005_v6_investigation'
down_revision = '004_v5_platform'
branch_labels = None
depends_on = None


def _col_exists(table, col):
    insp = sa.inspect(op.get_bind())
    if table not in insp.get_table_names():
        return False
    return col in [c['name'] for c in insp.get_columns(table)]


def upgrade():
    if not _col_exists('entity_link', 'confidence'):
        op.add_column('entity_link', sa.Column('confidence', sa.Float(), server_default='0.5'))
    if not _col_exists('entity_link', 'sources_json'):
        op.add_column('entity_link', sa.Column('sources_json', sa.Text()))
    if not _col_exists('entity_link', 'updated_at'):
        op.add_column('entity_link', sa.Column('updated_at', sa.DateTime()))

    if not _col_exists('investigation', 'objective'):
        op.add_column('investigation', sa.Column('objective', sa.Text()))
    if not _col_exists('investigation', 'status'):
        op.add_column('investigation', sa.Column('status', sa.String(20), server_default='pending'))
    if not _col_exists('investigation', 'steps_json'):
        op.add_column('investigation', sa.Column('steps_json', sa.Text()))
    if not _col_exists('investigation', 'result_summary'):
        op.add_column('investigation', sa.Column('result_summary', sa.Text()))
    if not _col_exists('investigation', 'completed_at'):
        op.add_column('investigation', sa.Column('completed_at', sa.DateTime()))


def downgrade():
    for table, cols in [
        ('entity_link', ['confidence', 'sources_json', 'updated_at']),
        ('investigation', ['objective', 'status', 'steps_json', 'result_summary', 'completed_at']),
    ]:
        for col in cols:
            if _col_exists(table, col):
                op.drop_column(table, col)
