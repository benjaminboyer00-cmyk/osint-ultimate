#!/usr/bin/env bash
# Validation locale avant VPS — syntaxe Compose + build image.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "→ docker compose config"
docker compose config > /dev/null

echo "→ build image (sans démarrer)"
docker compose build --pull=false

echo "→ compile Python dans l'image"
docker compose run --rm --no-deps web python -m compileall -q routes services app.py

echo "OK — stack prête."
echo "  Prod : docker compose up -d && curl -s http://127.0.0.1:7860/health"
echo "  Dev  : docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d"
