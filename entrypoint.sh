#!/bin/bash
set -e
cd /code

echo "[OSINT V4] Application des migrations base de données…"
export FLASK_APP=app:app
flask db upgrade 2>&1 || {
    echo "[OSINT V4] Alembic upgrade échoué – tentative create_all…"
    python -c "
from app import app, db
with app.app_context():
    db.create_all()
    print('[OSINT V4] Tables créées via create_all')
"
}

# Hugging Face : 1 worker, timeout long (scans sociaux), pas de preload (évite OOM au boot)
if [ -n "${SPACE_ID}" ] || [ -n "${SYSTEM}" ]; then
  export GUNICORN_WORKERS="${GUNICORN_WORKERS:-1}"
  export GUNICORN_TIMEOUT="${GUNICORN_TIMEOUT:-300}"
  export USE_CELERY="${USE_CELERY:-0}"
  export OSINT_IG_MODE="${OSINT_IG_MODE:-auto}"
  PRELOAD_FLAG=""
  echo "[OSINT] Mode Hugging Face — workers=1 timeout=${GUNICORN_TIMEOUT} USE_CELERY=${USE_CELERY}"
else
  PRELOAD_FLAG="--preload"
fi

WORKERS="${GUNICORN_WORKERS:-1}"
TIMEOUT="${GUNICORN_TIMEOUT:-120}"
MAX_REQ="${GUNICORN_MAX_REQUESTS:-1000}"
echo "[OSINT] Gunicorn workers=${WORKERS} timeout=${TIMEOUT}"
exec gunicorn -k gevent -w "${WORKERS}" -b 0.0.0.0:7860 \
  --timeout "${TIMEOUT}" --max-requests "${MAX_REQ}" ${PRELOAD_FLAG} app:app
