#!/bin/bash
set -e
cd /code

echo "[OSINT] Migrations Alembic (obligatoire avant Gunicorn)…"
export FLASK_APP=app:app
if ! flask db upgrade 2>&1; then
    echo "[OSINT] Alembic upgrade échoué — repli create_all…"
    if ! python -c "
from app import app, db
with app.app_context():
    db.create_all()
    print('[OSINT] Tables via create_all')
"; then
        echo "[OSINT] ERREUR: impossible d'initialiser la base"
        exit 1
    fi
    if [ -z "${SPACE_ID}" ] && [ -z "${SYSTEM}" ]; then
        echo "[OSINT] ERREUR VPS: corrigez DATABASE_URL et relancez (flask db upgrade requis)"
        exit 1
    fi
fi
echo "[OSINT] Migrations OK — $(flask db current 2>/dev/null || echo head)"

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
THREADS="${GUNICORN_THREADS:-8}"
TIMEOUT="${GUNICORN_TIMEOUT:-120}"
MAX_REQ="${GUNICORN_MAX_REQUESTS:-1000}"
echo "[OSINT] Gunicorn (gthread) workers=${WORKERS} threads=${THREADS} timeout=${TIMEOUT}"
exec gunicorn -k gthread -w "${WORKERS}" --threads "${THREADS}" -b 0.0.0.0:7860 \
  --timeout "${TIMEOUT}" --graceful-timeout 30 \
  --max-requests "${MAX_REQ}" --max-requests-jitter 100 \
  ${PRELOAD_FLAG} app:app
