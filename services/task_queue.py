"""File de tâches : Celery (Redis) ou thread local (défaut HF)."""
import logging
import os

logger = logging.getLogger(__name__)


def use_celery() -> bool:
    """True si REDIS_URL est défini et USE_CELERY n'est pas désactivé."""
    flag = (os.environ.get('USE_CELERY') or 'auto').strip().lower()
    if flag in ('0', 'false', 'no', 'off'):
        return False
    if flag in ('1', 'true', 'yes', 'force'):
        try:
            from celery_app import enabled
            return enabled
        except ImportError:
            return False
    # auto : Celery si broker configuré
    try:
        from celery_app import enabled
        return enabled
    except ImportError:
        return False


def enqueue_scan(scan_id: int, app, socketio=None, fernet=None):
    """
    Enfile le scan : Celery si disponible, sinon thread (comportement historique).
    Retourne le thread si mode thread, None si Celery.
    """
    if use_celery():
        try:
            from tasks import run_scan_task
            run_scan_task.delay(scan_id)
            logger.info('Scan #%s enfilé Celery', scan_id)
            return None
        except Exception as e:
            logger.warning('Celery indisponible, repli thread: %s', e)

    import threading
    from services.scan_runner import process_scan_by_id

    t = threading.Thread(
        target=process_scan_by_id,
        args=(scan_id, app, socketio, fernet),
        daemon=True,
        name=f'scan-{scan_id}',
    )
    t.start()
    return t
