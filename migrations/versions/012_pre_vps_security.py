"""Pré-VPS : 2FA, index performance."""
from alembic import op
import sqlalchemy as sa

revision = '012_pre_vps_security'
down_revision = '011_v8_collaboration'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('totp_secret_enc', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('totp_enabled', sa.Boolean(), nullable=False, server_default='false'))
    op.create_index('ix_scan_timestamp', 'scan', ['timestamp'], unique=False)
    op.create_index('ix_scan_created_status', 'scan', ['user_id', 'status'], unique=False)
    op.create_index('ix_entity_user_value', 'entity', ['user_id', 'value'], unique=False)


def downgrade():
    op.drop_index('ix_entity_user_value', table_name='entity')
    op.drop_index('ix_scan_created_status', table_name='scan')
    op.drop_index('ix_scan_timestamp', table_name='scan')
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('totp_enabled')
        batch_op.drop_column('totp_secret_enc')
