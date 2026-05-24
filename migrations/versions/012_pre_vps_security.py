"""Pré-VPS : 2FA, index performance (idempotent)."""
from alembic import op
import sqlalchemy as sa

revision = '012_pre_vps_security'
down_revision = '011_v8_collaboration'
branch_labels = None
depends_on = None


def _has_table(inspector, table: str) -> bool:
    return table in inspector.get_table_names()


def _table_columns(inspector, table: str) -> set:
    if not _has_table(inspector, table):
        return set()
    return {c['name'] for c in inspector.get_columns(table)}


def _table_indexes(inspector, table: str) -> set:
    if not _has_table(inspector, table):
        return set()
    return {i['name'] for i in inspector.get_indexes(table)}


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    user_cols = _table_columns(inspector, 'user')
    if 'totp_secret_enc' not in user_cols:
        op.add_column('user', sa.Column('totp_secret_enc', sa.Text(), nullable=True))
    if 'totp_enabled' not in user_cols:
        op.add_column(
            'user',
            sa.Column('totp_enabled', sa.Boolean(), nullable=False, server_default='false'),
        )

    scan_idx = _table_indexes(inspector, 'scan')
    # ix_scan_timestamp déjà créé en 001_v4_initial_schema
    if 'ix_scan_created_status' not in scan_idx:
        op.create_index('ix_scan_created_status', 'scan', ['user_id', 'status'], unique=False)

    entity_idx = _table_indexes(inspector, 'entity')
    if 'ix_entity_user_value' not in entity_idx:
        op.create_index('ix_entity_user_value', 'entity', ['user_id', 'value'], unique=False)


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    entity_idx = _table_indexes(inspector, 'entity')
    if 'ix_entity_user_value' in entity_idx:
        op.drop_index('ix_entity_user_value', table_name='entity')

    scan_idx = _table_indexes(inspector, 'scan')
    if 'ix_scan_created_status' in scan_idx:
        op.drop_index('ix_scan_created_status', table_name='scan')

    user_cols = _table_columns(inspector, 'user')
    if 'totp_enabled' in user_cols:
        op.drop_column('user', 'totp_enabled')
    if 'totp_secret_enc' in user_cols:
        op.drop_column('user', 'totp_secret_enc')
