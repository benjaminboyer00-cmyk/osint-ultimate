"""V5 — entités, liens, api_token, mode scan

Revision ID: 002_v5_entities
Revises: 001_v4_initial
Create Date: 2026-05-22

"""
from alembic import op
import sqlalchemy as sa

revision = '002_v5_entities'
down_revision = '001_v4_initial'
branch_labels = None
depends_on = None


def _insp():
    return sa.inspect(op.get_bind())


def _table_exists(name):
    return name in _insp().get_table_names()


def _col_exists(table, column):
    return column in [c['name'] for c in _insp().get_columns(table)]


def upgrade():
    if _table_exists('user') and not _col_exists('user', 'api_token'):
        op.add_column('user', sa.Column('api_token', sa.String(length=64), nullable=True))
        op.create_index('ix_user_api_token', 'user', ['api_token'], unique=True)

    if _table_exists('scan') and not _col_exists('scan', 'mode'):
        op.add_column('scan', sa.Column('mode', sa.String(length=20), nullable=True, server_default='expert'))

    if not _table_exists('entity'):
        op.create_table(
            'entity',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('user_id', sa.Integer(), nullable=False),
            sa.Column('entity_type', sa.String(length=30), nullable=False),
            sa.Column('value', sa.String(length=500), nullable=False),
            sa.Column('source_scan_id', sa.Integer(), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
            sa.ForeignKeyConstraint(['user_id'], ['user.id']),
            sa.ForeignKeyConstraint(['source_scan_id'], ['scan.id']),
            sa.PrimaryKeyConstraint('id'),
            sa.UniqueConstraint('user_id', 'entity_type', 'value', name='uq_entity_user_type_value'),
        )
        op.create_index('ix_entity_user_id', 'entity', ['user_id'])
        op.create_index('ix_entity_entity_type', 'entity', ['entity_type'])
        op.create_index('ix_entity_value', 'entity', ['value'])

    if not _table_exists('entity_link'):
        op.create_table(
            'entity_link',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('user_id', sa.Integer(), nullable=False),
            sa.Column('source_id', sa.Integer(), nullable=False),
            sa.Column('target_id', sa.Integer(), nullable=False),
            sa.Column('link_type', sa.String(length=50), nullable=False),
            sa.Column('source_proof', sa.String(length=500), nullable=True),
            sa.Column('scan_id', sa.Integer(), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
            sa.ForeignKeyConstraint(['user_id'], ['user.id']),
            sa.ForeignKeyConstraint(['source_id'], ['entity.id']),
            sa.ForeignKeyConstraint(['target_id'], ['entity.id']),
            sa.ForeignKeyConstraint(['scan_id'], ['scan.id']),
            sa.PrimaryKeyConstraint('id'),
        )
        op.create_index('ix_entity_link_user_id', 'entity_link', ['user_id'])


def downgrade():
    op.drop_table('entity_link')
    op.drop_table('entity')
    if _col_exists('scan', 'mode'):
        op.drop_column('scan', 'mode')
    if _col_exists('user', 'api_token'):
        op.drop_index('ix_user_api_token', table_name='user')
        op.drop_column('user', 'api_token')
