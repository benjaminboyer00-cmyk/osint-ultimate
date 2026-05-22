"""Configuration Celery — actif si REDIS_URL est défini."""
import os

broker = os.environ.get('REDIS_URL') or os.environ.get('CELERY_BROKER_URL', '')
enabled = bool(broker)

if enabled:
    from celery import Celery

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
    )
else:
    celery_app = None
