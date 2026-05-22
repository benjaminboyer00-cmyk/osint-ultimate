"""V5 — cache, webhooks, investigation, préférences utilisateur

Revision ID: 004_v5_platform
Revises: 003_v5_scheduled
"""
from alembic import op
import sqlalchemy as sa

revision = '004_v5_platform'
down_revision = '003_v5_scheduled'
branch_labels = None
depends_on = None


def _table_exists(name):
    return name in sa.inspect(op.get_bind()).get_table_names()


def upgrade():
    if not _table_exists('api_cache'):
        op.create_table(
            'api_cache',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('provider', sa.String(40), nullable=False),
            sa.Column('cache_key', sa.String(64), nullable=False),
            sa.Column('query', sa.String(500)),
            sa.Column('payload', sa.Text(), nullable=False),
            sa.Column('expires_at', sa.DateTime(), nullable=False),
            sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP')),
        )
        op.create_index('ix_api_cache_cache_key', 'api_cache', ['cache_key'], unique=True)

    if not _table_exists('webhook'):
        op.create_table(
            'webhook',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=False),
            sa.Column('url', sa.String(500), nullable=False),
            sa.Column('enabled', sa.Boolean(), server_default='true'),
            sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP')),
        )

    if not _table_exists('investigation'):
        op.create_table(
            'investigation',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=False),
            sa.Column('title', sa.String(200), nullable=False),
            sa.Column('root_entity_id', sa.Integer(), sa.ForeignKey('entity.id')),
            sa.Column('notes', sa.Text()),
            sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP')),
            sa.Column('updated_at', sa.DateTime()),
        )

    if not _table_exists('investigation_message'):
        op.create_table(
            'investigation_message',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=False),
            sa.Column('role', sa.String(20), nullable=False),
            sa.Column('content', sa.Text(), nullable=False),
            sa.Column('suggested_actions', sa.Text()),
            sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP')),
        )

    bind = op.get_bind()
    insp = sa.inspect(bind)
    if 'user' in insp.get_table_names():
        cols = [c['name'] for c in insp.get_columns('user')]
        if 'proxy_list' not in cols:
            op.add_column('user', sa.Column('proxy_list', sa.Text()))
        if 'stealth_mode' not in cols:
            op.add_column('user', sa.Column('stealth_mode', sa.Boolean(), server_default='false'))
        if 'locale' not in cols:
            op.add_column('user', sa.Column('locale', sa.String(5), server_default='fr'))

    if 'scheduled_scan' in insp.get_table_names():
        cols = [c['name'] for c in insp.get_columns('scheduled_scan')]
        if 'webhook_url' not in cols:
            op.add_column('scheduled_scan', sa.Column('webhook_url', sa.String(500)))


def downgrade():
    op.drop_table('investigation_message')
    op.drop_table('investigation')
    op.drop_table('webhook')
    op.drop_table('api_cache')
