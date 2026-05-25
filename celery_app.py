"""Configuration Celery — actif si REDIS_URL est défini."""
import os

broker = os.environ.get('REDIS_URL') or os.environ.get('CELERY_BROKER_URL', '')
enabled = bool(broker)

if enabled:
    from celery import Celery
    from celery.schedules import crontab

    celery_app = Celery(
        'osint_ultimate',
        broker=broker,
        backend=broker,
        include=['tasks'],
    )
    celery_app.conf.update(
        task_serializer='json',
        result_serializer='json',
        accept_content=['json'],
        timezone='UTC',
        task_track_started=True,
        task_time_limit=600,
        worker_prefetch_multiplier=1,
        beat_schedule={
            'scheduled-scans-every-5min': {
                'task': 'osint.scheduled_tick',
                'schedule': 300.0,
            },
            'daily-backup': {
                'task': 'osint.backup_daily',
                'schedule': crontab(hour=2, minute=30),
            },
            'weekly-data-retention': {
                'task': 'osint.data_retention',
                'schedule': crontab(hour=3, minute=0, day_of_week=0),
            },
        },
    )
else:
    celery_app = None
