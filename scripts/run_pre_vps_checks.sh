#!/usr/bin/env bash
# Vérifications pré-VPS — à lancer depuis la racine du projet.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "=== 1. Environnement Python ==="
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
  .venv/bin/pip install -q -r requirements.txt pytest pytest-cov
fi
# shellcheck disable=SC1091
source .venv/bin/activate
export FLASK_APP=app:app

echo "=== 2. Tests (pytest — SQLite mémoire, pas Supabase) ==="
# Sauvegarde DATABASE_URL prod pour la migration plus bas
_SAVED_DB_URL="${DATABASE_URL:-}"
export DATABASE_URL="sqlite:///:memory:"
python -m pytest tests/ -q --tb=line
export DATABASE_URL="$_SAVED_DB_URL"

echo "=== 3. Connexion DB + migration Alembic ==="
if [[ -z "${DATABASE_URL:-}" ]]; then
  echo "⚠️  DATABASE_URL non défini — voir docs/SUPABASE_CONNECTION.md"
else
  if python scripts/check_database.py; then
    flask db upgrade
    echo "✓ Migration OK (révision actuelle) :"
    flask db current
  else
    echo "⚠️  Migration ignorée — corrigez DATABASE_URL (docs/SUPABASE_CONNECTION.md)"
    echo "    Les tests pytest ci-dessus sont OK sans Supabase."
  fi
fi

echo "=== 4. Docker Compose (syntaxe) ==="
if command -v docker >/dev/null 2>&1; then
  docker compose config > /dev/null && echo "✓ docker-compose.yml valide"
  if [[ "${SKIP_DOCKER_BUILD:-}" != "1" ]]; then
    echo "    (SKIP_DOCKER_BUILD=1 pour ignorer le build)"
    docker compose build 2>/dev/null || echo "⚠️  Build Docker ignoré ou échoué"
  fi
else
  echo "⚠️  Docker non installé — étape ignorée"
fi

echo ""
echo "=== Terminé ==="
