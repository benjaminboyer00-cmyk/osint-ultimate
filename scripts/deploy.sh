#!/usr/bin/env bash
# Déploiement VPS — tirer l'image et relancer la stack Docker.
set -euo pipefail

IMAGE_TAG="${1:-latest}"
APP_DIR="${APP_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
COMPOSE_FILE="${COMPOSE_FILE:-$APP_DIR/docker-compose.yml}"
REGISTRY_IMAGE="${REGISTRY_IMAGE:-ghcr.io/OWNER/osint-ultimate}"

cd "$APP_DIR"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

export IMAGE_TAG
export WEB_IMAGE="${REGISTRY_IMAGE}:${IMAGE_TAG}"

echo "→ Pull ${WEB_IMAGE}"
docker compose -f "$COMPOSE_FILE" pull web worker beat 2>/dev/null || docker pull "$WEB_IMAGE"

echo "→ Up stack"
docker compose -f "$COMPOSE_FILE" up -d

echo "→ Migrations"
docker compose -f "$COMPOSE_FILE" exec -T web flask db upgrade || true

echo "→ Health"
sleep 3
curl -fsS "http://127.0.0.1:${PORT:-7860}/health" | head -c 500
echo ""
echo "Déploiement terminé."
