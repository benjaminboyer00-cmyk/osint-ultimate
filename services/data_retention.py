"""Politique de rétention — uploads, cache SQL, entrées Redis expirées."""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)


def purge_uploads(max_age_days: int | None = None) -> dict:
    """Supprime les fichiers uploads/ plus anciens que max_age_days."""
    days = max_age_days if max_age_days is not None else int(
        os.environ.get('RETENTION_UPLOAD_DAYS', '30'),
    )
    root = Path(os.environ.get('UPLOAD_FOLDER', 'uploads'))
    if not root.is_dir():
        return {'ok': True, 'skipped': True, 'reason': 'dossier uploads absent'}

    cutoff = datetime.utcnow() - timedelta(days=max(1, days))
    removed = 0
    freed = 0
    for path in root.rglob('*'):
        if not path.is_file():
            continue
        try:
            mtime = datetime.utcfromtimestamp(path.stat().st_mtime)
            if mtime < cutoff:
                size = path.stat().st_size
                path.unlink()
                removed += 1
                freed += size
        except OSError as e:
            logger.warning('purge_uploads %s: %s', path, e)

    return {
        'ok': True,
        'removed_files': removed,
        'freed_bytes': freed,
        'max_age_days': days,
    }


def purge_api_cache_expired() -> dict:
    """Supprime les lignes api_cache dont expires_at est dépassé."""
    from extensions import db
    from models import ApiCache

    now = datetime.utcnow()
    try:
        q = db.session.query(ApiCache).filter(ApiCache.expires_at < now)
        count = q.count()
        q.delete(synchronize_session=False)
        from services.db_session import safe_commit
        safe_commit(db.session)
        return {'ok': True, 'removed_rows': count}
    except Exception as e:
        db.session.rollback()
        logger.exception('purge_api_cache_expired')
        return {'ok': False, 'error': str(e)}


def trim_redis_cache_db() -> dict:
    """
    Nettoie les clés lookup:* sans TTL sur la DB Redis cache (si REDIS_CACHE_DB défini).
    Ne touche pas au broker Celery (db 0) ni au rate-limit (db 1).
    """
    db_index = os.environ.get('REDIS_CACHE_DB', '').strip()
    if not db_index:
        return {'ok': True, 'skipped': True, 'reason': 'REDIS_CACHE_DB non configuré'}

    base = os.environ.get('REDIS_URL') or os.environ.get('CELERY_BROKER_URL', '')
    if not base:
        return {'ok': True, 'skipped': True, 'reason': 'REDIS_URL absent'}

    try:
        import redis
        # Remplacer le numéro de DB dans l'URL
        from urllib.parse import urlparse, urlunparse
        p = urlparse(base)
        path = f'/{db_index}'
        url = urlunparse((p.scheme, p.netloc, path, '', '', ''))
        client = redis.from_url(url, decode_responses=True, socket_connect_timeout=5)
        deleted = 0
        for key in client.scan_iter('lookup:*', count=500):
            if client.ttl(key) == -1:
                client.delete(key)
                deleted += 1
        return {'ok': True, 'deleted_keys': deleted, 'db': db_index}
    except Exception as e:
        logger.warning('trim_redis_cache_db: %s', e)
        return {'ok': False, 'error': str(e)}


def run_retention_cycle() -> dict:
    """Cycle complet — appelé par Celery beat (hebdomadaire)."""
    return {
        'uploads': purge_uploads(),
        'api_cache': purge_api_cache_expired(),
        'redis': trim_redis_cache_db(),
        'at': datetime.utcnow().isoformat() + 'Z',
    }
