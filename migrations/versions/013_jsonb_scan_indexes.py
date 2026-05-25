"""Index JSONB sur scan.result_json et entity.meta_json (PostgreSQL)."""
from alembic import op
import sqlalchemy as sa


revision = '013_jsonb_scan_indexes'
down_revision = '012_pre_vps_security'
branch_labels = None
depends_on = None


def _is_postgres(conn):
    return conn.dialect.name == 'postgresql'


def upgrade():
    conn = op.get_bind()
    if not _is_postgres(conn):
        return
    # Résultats de scan : requêtes pivot / corrélation sur clés JSON
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_scan_result_json_gin
        ON scan USING gin ((result_json::jsonb) jsonb_path_ops)
        WHERE result_json IS NOT NULL AND result_json <> ''
        """
    )
    # meta_json sur entity si la colonne existe
    insp = sa.inspect(conn)
    if 'entity' in insp.get_table_names():
        cols = {c['name'] for c in insp.get_columns('entity')}
        if 'meta_json' in cols:
            op.execute(
                """
                CREATE INDEX IF NOT EXISTS ix_entity_meta_json_gin
                ON entity USING gin ((meta_json::jsonb) jsonb_path_ops)
                WHERE meta_json IS NOT NULL AND meta_json <> ''
                """
            )


def downgrade():
    conn = op.get_bind()
    if not _is_postgres(conn):
        return
    op.execute('DROP INDEX IF EXISTS ix_scan_result_json_gin')
    op.execute('DROP INDEX IF EXISTS ix_entity_meta_json_gin')
