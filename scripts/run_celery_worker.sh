#!/bin/bash
# Worker Celery OSINT Ultimate (à lancer à côté de Gunicorn si REDIS_URL est défini)
set -e
cd "$(dirname "$0")/.."
export FLASK_APP=app:app
exec celery -A celery_app:celery_app worker -l info --concurrency=2
