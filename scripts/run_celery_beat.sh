#!/bin/bash
# Beat Celery — surveillances programmées (désactive APScheduler si USE_CELERY_BEAT=true)
set -e
cd "$(dirname "$0")/.."
export FLASK_APP=app:app
export USE_CELERY_BEAT=true
exec celery -A celery_app:celery_app beat -l info
