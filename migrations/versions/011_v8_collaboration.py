"""V8 — Collaboration sur dossiers (partage, commentaires, activité)

Revision ID: 011_v8_collaboration
Revises: 010_v7_monitoring_alerts
"""
from alembic import op
import sqlalchemy as sa

revision = '011_v8_collaboration'
down_revision = '010_v7_monitoring_alerts'
branch_labels = None
depends_on = None


def _table_exists(name):
    return name in sa.inspect(op.get_bind()).get_table_names()


def upgrade():
    if not _table_exists('dossier_collaborator'):
        op.create_table(
            'dossier_collaborator',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('root_entity_id', sa.Integer(), sa.ForeignKey('entity.id'), nullable=False, index=True),
            sa.Column('user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=False, index=True),
            sa.Column('invited_by_user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=True),
            sa.Column('role', sa.String(20), nullable=False, server_default='reader'),
            sa.Column('invited_at', sa.DateTime(), nullable=False),
            sa.Column('accepted_at', sa.DateTime(), nullable=True),
            sa.UniqueConstraint('root_entity_id', 'user_id', name='uq_dossier_collab_entity_user'),
        )

    if not _table_exists('entity_comment'):
        op.create_table(
            'entity_comment',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('entity_id', sa.Integer(), sa.ForeignKey('entity.id'), nullable=False, index=True),
            sa.Column('user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=False, index=True),
            sa.Column('content', sa.Text(), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
        )

    if not _table_exists('dossier_activity_log'):
        op.create_table(
            'dossier_activity_log',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('root_entity_id', sa.Integer(), sa.ForeignKey('entity.id'), nullable=False, index=True),
            sa.Column('user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=True, index=True),
            sa.Column('action', sa.String(50), nullable=False),
            sa.Column('details_json', sa.Text(), nullable=True),
            sa.Column('timestamp', sa.DateTime(), nullable=False),
        )

    if not _table_exists('collaboration_notification'):
        op.create_table(
            'collaboration_notification',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=False, index=True),
            sa.Column('message', sa.String(500), nullable=False),
            sa.Column('link', sa.String(500), nullable=True),
            sa.Column('notification_type', sa.String(30), server_default='invite'),
            sa.Column('read', sa.Boolean(), server_default=sa.false(), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
        )

    bind = op.get_bind()
    insp = sa.inspect(bind)
    if 'scan' in insp.get_table_names():
        cols = [c['name'] for c in insp.get_columns('scan')]
        if 'root_entity_id' not in cols:
            op.add_column(
                'scan',
                sa.Column('root_entity_id', sa.Integer(), sa.ForeignKey('entity.id'), nullable=True),
            )
            op.create_index('ix_scan_root_entity_id', 'scan', ['root_entity_id'])


def downgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if 'scan' in insp.get_table_names():
        cols = [c['name'] for c in insp.get_columns('scan')]
        if 'root_entity_id' in cols:
            op.drop_index('ix_scan_root_entity_id', table_name='scan')
            op.drop_column('scan', 'root_entity_id')
    for t in ('collaboration_notification', 'dossier_activity_log', 'entity_comment', 'dossier_collaborator'):
        if _table_exists(t):
            op.drop_table(t)
