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

echo "[OSINT V4] Démarrage Gunicorn sur le port 7860…"
exec gunicorn -k gevent -w 1 -b 0.0.0.0:7860 --timeout 120 app:app
