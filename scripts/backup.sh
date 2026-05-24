#!/usr/bin/env bash
# Sauvegarde manuelle (cron VPS ou one-shot).
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

if docker compose ps web 2>/dev/null | grep -q Up; then
  docker compose exec -T web python -c "
from app import app
from services.backup import run_all_backups
with app.app_context():
    import json
    print(json.dumps(run_all_backups(), indent=2))
"
else
  python3 -c "
from app import app
from services.backup import run_all_backups
with app.app_context():
    import json
    print(json.dumps(run_all_backups(), indent=2))
"
fi
