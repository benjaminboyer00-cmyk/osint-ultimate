#!/usr/bin/env bash
# Let's Encrypt — Nginx + Certbot (VPS production).
# Usage : DOMAIN=osint.example.com EMAIL=admin@example.com ./scripts/certbot-setup.sh
set -euo pipefail

DOMAIN="${DOMAIN:?Définir DOMAIN=votredomaine.io}"
EMAIL="${EMAIL:-}"
APP_DIR="${APP_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
NGINX_SITE="/etc/nginx/sites-available/osint-ultimate"
NGINX_ENABLED="/etc/nginx/sites-enabled/osint-ultimate"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Exécuter en root : sudo DOMAIN=$DOMAIN EMAIL=$EMAIL $0"
  exit 1
fi

echo "→ Installation certbot (si absent)"
if ! command -v certbot >/dev/null 2>&1; then
  apt-get update
  apt-get install -y certbot python3-certbot-nginx
fi

echo "→ Déploiement config Nginx"
sed "s/osint.example.com/${DOMAIN}/g" "$APP_DIR/deploy/nginx.conf" > "$NGINX_SITE"
ln -sf "$NGINX_SITE" "$NGINX_ENABLED"
mkdir -p /var/www/certbot

echo "→ Test Nginx (HTTP seulement pour ACME)"
nginx -t
systemctl reload nginx

CERTBOT_ARGS=(--nginx -d "$DOMAIN" --agree-tos --non-interactive --redirect)
if [[ -n "$EMAIL" ]]; then
  CERTBOT_ARGS+=(--email "$EMAIL")
else
  CERTBOT_ARGS+=(--register-unsafely-without-email)
fi

echo "→ Certificat Let's Encrypt"
certbot "${CERTBOT_ARGS[@]}"

echo "→ Renouvellement auto (timer systemd certbot)"
systemctl enable certbot.timer 2>/dev/null || true
systemctl start certbot.timer 2>/dev/null || true

echo "OK — HTTPS actif pour https://${DOMAIN}"
echo "Vérifiez proxy_read_timeout 120s dans $NGINX_SITE"
