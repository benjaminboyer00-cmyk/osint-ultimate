"""V7 Phase 7 — Règles d'alerte surveillance + historique

Revision ID: 010_v7_monitoring_alerts
Revises: 009_v7_entity_geo
"""
from alembic import op
import sqlalchemy as sa

revision = '010_v7_monitoring_alerts'
down_revision = '009_v7_entity_geo'
branch_labels = None
depends_on = None


def _table_exists(name):
    return name in sa.inspect(op.get_bind()).get_table_names()


def _col_exists(table, col):
    insp = sa.inspect(op.get_bind())
    if table not in insp.get_table_names():
        return False
    return col in [c['name'] for c in insp.get_columns(table)]


def upgrade():
    if not _col_exists('scheduled_scan', 'alert_rules_json'):
        op.add_column('scheduled_scan', sa.Column('alert_rules_json', sa.Text(), nullable=True))
    if not _col_exists('scheduled_scan', 'last_snapshot_json'):
        op.add_column('scheduled_scan', sa.Column('last_snapshot_json', sa.Text(), nullable=True))

    if not _table_exists('monitoring_alert'):
        op.create_table(
            'monitoring_alert',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=False, index=True),
            sa.Column('job_id', sa.Integer(), sa.ForeignKey('scheduled_scan.id'), nullable=True, index=True),
            sa.Column('scan_id', sa.Integer(), sa.ForeignKey('scan.id'), nullable=True),
            sa.Column('level', sa.String(20), nullable=False, server_default='info'),
            sa.Column('alert_type', sa.String(50), nullable=False),
            sa.Column('message', sa.Text(), nullable=False),
            sa.Column('details_json', sa.Text(), nullable=True),
            sa.Column('read', sa.Boolean(), nullable=False, server_default='false'),
            sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        )


def downgrade():
    if _table_exists('monitoring_alert'):
        op.drop_table('monitoring_alert')
    if _col_exists('scheduled_scan', 'last_snapshot_json'):
        op.drop_column('scheduled_scan', 'last_snapshot_json')
    if _col_exists('scheduled_scan', 'alert_rules_json'):
        op.drop_column('scheduled_scan', 'alert_rules_json')
