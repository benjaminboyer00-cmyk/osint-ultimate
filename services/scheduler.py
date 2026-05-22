"""Scans programmés — APScheduler."""
from datetime import datetime, timedelta

_scheduler = None


def start_scheduler(app):
    global _scheduler
    if _scheduler is not None:
        return _scheduler

    import os
    try:
        from services.task_queue import use_celery
        if use_celery() and os.environ.get('USE_CELERY_BEAT', '').lower() in ('1', 'true', 'yes'):
            app.logger.info(
                'APScheduler désactivé — lancer: celery -A celery_app:celery_app beat'
            )
            return None
    except Exception:
        pass

    try:
        from apscheduler.schedulers.background import BackgroundScheduler
    except ImportError:
        app.logger.warning('APScheduler non installé — scans programmés désactivés')
        return None

    _scheduler = BackgroundScheduler(daemon=True)

    def tick():
        with app.app_context():
            run_due_scheduled_scans(app)

    _scheduler.add_job(tick, 'interval', minutes=5, id='osint_scheduled_scans', replace_existing=True)
    _scheduler.start()
    app.logger.info('Scheduler scans programmés démarré (toutes les 5 min)')
    return _scheduler


def run_due_scheduled_scans(app):
    from models import ScheduledScan
    from extensions import db

    now = datetime.utcnow()
    due = ScheduledScan.query.filter(
        ScheduledScan.enabled == True,
        ScheduledScan.next_run_at <= now,
    ).all()

    for job in due:
        try:
            from app import run_scan_async
            scan_id = run_scan_async(
                job.module,
                job.target,
                user_id=job.user_id,
                mode='expert',
                scheduled_scan_id=job.id,
            )
            job.last_run_at = now
            job.last_scan_id = scan_id
            job.next_run_at = now + timedelta(hours=job.interval_hours or 24)
            db.session.commit()
            app.logger.info('Scan programmé #%s lancé → scan %s', job.id, scan_id)
        except Exception as exc:
            app.logger.error('Scan programmé #%s échoué: %s', job.id, exc)
            db.session.rollback()
