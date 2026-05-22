"""V7 Phase 4 — Empreinte PDF scellée pour vérification

Revision ID: 008_v7_report_seal
Revises: 007_v8_scrape_pref
"""
from alembic import op
import sqlalchemy as sa

revision = '008_v7_report_seal'
down_revision = '007_v8_scrape_pref'
branch_labels = None
depends_on = None


def _col_exists(table, col):
    insp = sa.inspect(op.get_bind())
    if table not in insp.get_table_names():
        return False
    return col in [c['name'] for c in insp.get_columns(table)]


def upgrade():
    if not _col_exists('scan', 'report_pdf_hash'):
        op.add_column('scan', sa.Column('report_pdf_hash', sa.String(64), nullable=True))
    if not _col_exists('scan', 'report_sealed_at'):
        op.add_column('scan', sa.Column('report_sealed_at', sa.DateTime(), nullable=True))


def downgrade():
    if _col_exists('scan', 'report_sealed_at'):
        op.drop_column('scan', 'report_sealed_at')
    if _col_exists('scan', 'report_pdf_hash'):
        op.drop_column('scan', 'report_pdf_hash')
