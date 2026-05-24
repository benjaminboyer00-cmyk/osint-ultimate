"""Utilitaires DB pour les tests — évite drop_all sur cycles FK."""
from __future__ import annotations

from sqlalchemy import text

# Ordre enfant → parent (suppression des lignes)
TABLE_CLEAR_ORDER = (
    'collaboration_notification',
    'dossier_activity_log',
    'entity_comment',
    'dossier_collaborator',
    'entity_link',
    'investigation_message',
    'monitoring_alert',
    'scan',
    'investigation',
    'scheduled_scan',
    'entity',
    'recipe',
    'api_cache',
    'webhook',
    'user',
)


def clear_all_rows(db) -> None:
    """Vide les tables sans DROP (compatible cycles entity/scan/scheduled_scan)."""
    bind = db.session.get_bind()
    dialect = bind.dialect.name
    if dialect == 'sqlite':
        db.session.execute(text('PRAGMA foreign_keys = OFF'))
    for table in TABLE_CLEAR_ORDER:
        try:
            db.session.execute(text(f'DELETE FROM {table}'))
        except Exception:
            db.session.rollback()
    if dialect == 'sqlite':
        db.session.execute(text('PRAGMA foreign_keys = ON'))
    db.session.commit()

