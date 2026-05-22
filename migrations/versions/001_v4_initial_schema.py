"""Schéma V4 – création ou mise à niveau (Supabase / SQLite / HF)

Revision ID: 001_v4_initial
Revises:
Create Date: 2026-05-22

"""
from alembic import op
import sqlalchemy as sa

revision = '001_v4_initial'
down_revision = None
branch_labels = None
depends_on = None


def _insp():
    return sa.inspect(op.get_bind())


def _table_exists(name):
    return name in _insp().get_table_names()


def _col_exists(table, column):
    return column in [c['name'] for c in _insp().get_columns(table)]


def _index_exists(table, name):
    return name in [i['name'] for i in _insp().get_indexes(table)]


def upgrade():
    if not _table_exists('user'):
        op.create_table(
            'user',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('username', sa.String(length=80), nullable=False),
            sa.Column('email', sa.String(length=120), nullable=False),
            sa.Column('password_hash', sa.String(length=256), nullable=True),
            sa.Column('api_keys_enc', sa.Text(), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
            sa.Column('last_login', sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint('id'),
        )
        op.create_index('ix_user_username', 'user', ['username'], unique=True)
        op.create_index('ix_user_email', 'user', ['email'], unique=True)
    else:
        if not _col_exists('user', 'created_at'):
            op.add_column('user', sa.Column('created_at', sa.DateTime(), nullable=True))
            op.execute(sa.text('UPDATE "user" SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL'))
        if not _col_exists('user', 'last_login'):
            op.add_column('user', sa.Column('last_login', sa.DateTime(), nullable=True))

    if not _table_exists('scan'):
        op.create_table(
            'scan',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('user_id', sa.Integer(), nullable=True),
            sa.Column('module', sa.String(length=50), nullable=False),
            sa.Column('target', sa.String(length=500), nullable=False),
            sa.Column('result_json', sa.Text(), nullable=True),
            sa.Column('ai_summary', sa.Text(), nullable=True),
            sa.Column('timestamp', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
            sa.Column('completed_at', sa.DateTime(), nullable=True),
            sa.Column('status', sa.String(length=20), nullable=False, server_default='pending'),
            sa.ForeignKeyConstraint(['user_id'], ['user.id']),
            sa.PrimaryKeyConstraint('id'),
        )
        op.create_index('ix_scan_user_id', 'scan', ['user_id'], unique=False)
        op.create_index('ix_scan_timestamp', 'scan', ['timestamp'], unique=False)
        op.create_index('ix_scan_status', 'scan', ['status'], unique=False)
    else:
        if not _col_exists('scan', 'ai_summary'):
            op.add_column('scan', sa.Column('ai_summary', sa.Text(), nullable=True))
        if not _col_exists('scan', 'completed_at'):
            op.add_column('scan', sa.Column('completed_at', sa.DateTime(), nullable=True))
        for idx, cols in [
            ('ix_scan_user_id', ['user_id']),
            ('ix_scan_timestamp', ['timestamp']),
            ('ix_scan_status', ['status']),
        ]:
            if not _index_exists('scan', idx):
                op.create_index(idx, 'scan', cols, unique=False)


def downgrade():
    op.drop_table('scan')
    op.drop_table('user')
