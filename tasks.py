"""Tâches Celery — scans et surveillance (Phase 10)."""
import json
import logging
import os

logger = logging.getLogger(__name__)

try:
    from celery_app import celery_app, enabled
except ImportError:
    enabled = False
    celery_app = None


def _app_context():
    from app import app, fernet
    return app, fernet


if enabled and celery_app:

    @celery_app.task(bind=True, name='osint.run_scan', max_retries=1)
    def run_scan_task(self, scan_id: int):
        """Exécute un scan via process_scan_by_id (même logique que le thread)."""
        from services.scan_runner import process_scan_by_id

        app, fernet = _app_context()
        self.update_state(state='PROGRESS', meta={'scan_id': scan_id, 'step': 'running'})
        try:
            process_scan_by_id(scan_id, app, socketio=None, fernet=fernet)
            return {'scan_id': scan_id, 'status': 'completed'}
        except Exception as e:
            logger.exception('Celery scan #%s', scan_id)
            raise self.retry(exc=e, countdown=5) if self.request.retries < 1 else e

    @celery_app.task(name='osint.scheduled_tick')
    def scheduled_tick_task():
        """Tick surveillance — équivalent APScheduler, exécutable par beat/worker."""
        app, _ = _app_context()
        with app.app_context():
            from services.scheduler import run_due_scheduled_scans
            run_due_scheduled_scans(app)
        return {'ok': True}

else:

    def run_scan_task(*args, **kwargs):
        raise RuntimeError('Celery désactivé — définir REDIS_URL')

    def scheduled_tick_task(*args, **kwargs):
        raise RuntimeError('Celery désactivé')
