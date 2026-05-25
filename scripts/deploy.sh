#!/usr/bin/env bash
# Déploiement VPS — pull image, stack Docker, migrations, health, SSL optionnel.
set -euo pipefail

IMAGE_TAG="${1:-latest}"
APP_DIR="${APP_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
COMPOSE_FILE="${COMPOSE_FILE:-$APP_DIR/docker-compose.yml}"
REGISTRY_IMAGE="${REGISTRY_IMAGE:-ghcr.io/OWNER/osint-ultimate}"
DOMAIN="${DOMAIN:-}"
RUN_CERTBOT="${RUN_CERTBOT:-0}"

cd "$APP_DIR"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

export IMAGE_TAG
export WEB_IMAGE="${REGISTRY_IMAGE}:${IMAGE_TAG}"

echo "→ Validation compose"
docker compose -f "$COMPOSE_FILE" config > /dev/null

echo "→ Pull ${WEB_IMAGE}"
docker compose -f "$COMPOSE_FILE" pull web worker beat 2>/dev/null || docker pull "$WEB_IMAGE" || true

echo "→ Build (si image locale)"
docker compose -f "$COMPOSE_FILE" build web 2>/dev/null || true

echo "→ Up stack (migrations dans entrypoint web avant Gunicorn)"
docker compose -f "$COMPOSE_FILE" up -d

echo "→ Attente healthcheck web"
for i in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:${PORT:-7860}/health" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

echo "→ Health"
curl -fsS "http://127.0.0.1:${PORT:-7860}/health" | head -c 500
echo ""

echo "→ Migrations (vérif post-démarrage)"
docker compose -f "$COMPOSE_FILE" exec -T web flask db current 2>/dev/null || true

if [[ "$RUN_CERTBOT" == "1" && -n "$DOMAIN" ]]; then
  echo "→ SSL Certbot pour $DOMAIN"
  if [[ "$(id -u)" -eq 0 ]]; then
    DOMAIN="$DOMAIN" EMAIL="${CERTBOT_EMAIL:-}" "$APP_DIR/scripts/certbot-setup.sh"
  else
    echo "Relancer en root : sudo RUN_CERTBOT=1 DOMAIN=$DOMAIN ./scripts/deploy.sh $IMAGE_TAG"
  fi
fi

echo "Déploiement terminé."
echo "  Nginx : proxy vers 127.0.0.1:${PORT:-7860}"
echo "  Logs  : docker compose logs -f --tail=100 web worker"
