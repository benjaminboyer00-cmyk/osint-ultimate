"""Scans programmés + lien scan planifié

Revision ID: 003_v5_scheduled
Revises: 002_v5_entities
Create Date: 2026-05-22

"""
from alembic import op
import sqlalchemy as sa

revision = '003_v5_scheduled'
down_revision = '002_v5_entities'
branch_labels = None
depends_on = None


def _insp():
    return sa.inspect(op.get_bind())


def _table_exists(name):
    return name in _insp().get_table_names()


def _col_exists(table, column):
    return column in [c['name'] for c in _insp().get_columns(table)]


def upgrade():
    if not _table_exists('scheduled_scan'):
        op.create_table(
            'scheduled_scan',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('user_id', sa.Integer(), nullable=False),
            sa.Column('module', sa.String(length=50), nullable=False),
            sa.Column('target', sa.String(length=500), nullable=False),
            sa.Column('interval_hours', sa.Integer(), nullable=False, server_default='24'),
            sa.Column('enabled', sa.Boolean(), nullable=False, server_default='true'),
            sa.Column('last_run_at', sa.DateTime(), nullable=True),
            sa.Column('next_run_at', sa.DateTime(), nullable=True),
            sa.Column('last_scan_id', sa.Integer(), nullable=True),
            sa.Column('notify_on_change', sa.Boolean(), nullable=False, server_default='false'),
            sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
            sa.ForeignKeyConstraint(['user_id'], ['user.id']),
            sa.ForeignKeyConstraint(['last_scan_id'], ['scan.id']),
            sa.PrimaryKeyConstraint('id'),
        )
        op.create_index('ix_scheduled_scan_user_id', 'scheduled_scan', ['user_id'])
        op.create_index('ix_scheduled_scan_next_run_at', 'scheduled_scan', ['next_run_at'])

    if _table_exists('scan') and not _col_exists('scan', 'scheduled_scan_id'):
        op.add_column('scan', sa.Column('scheduled_scan_id', sa.Integer(), nullable=True))
        op.create_foreign_key(
            'fk_scan_scheduled_scan', 'scan', 'scheduled_scan',
            ['scheduled_scan_id'], ['id'],
        )


def downgrade():
    if _col_exists('scan', 'scheduled_scan_id'):
        op.drop_constraint('fk_scan_scheduled_scan', 'scan', type_='foreignkey')
        op.drop_column('scan', 'scheduled_scan_id')
    op.drop_table('scheduled_scan')
