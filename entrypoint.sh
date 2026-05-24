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

WORKERS="${GUNICORN_WORKERS:-1}"
TIMEOUT="${GUNICORN_TIMEOUT:-120}"
MAX_REQ="${GUNICORN_MAX_REQUESTS:-1000}"
echo "[OSINT] Gunicorn workers=${WORKERS} timeout=${TIMEOUT}"
exec gunicorn -k gevent -w "${WORKERS}" -b 0.0.0.0:7860 \
  --timeout "${TIMEOUT}" --max-requests "${MAX_REQ}" --preload app:app
