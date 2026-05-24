# Déploiement VPS (Nginx + Docker)

## Prérequis

- Domaine + DNS vers le VPS
- Docker + docker-compose
- Variables dans `.env` (copier depuis `SECRETS.md`)

## Démarrage local (stack complète)

```bash
cp .env.example .env   # si présent, sinon créer .env
docker compose up -d --build
curl http://localhost:7860/health
```

## Nginx

Fichier complet prêt à l’emploi : **`deploy/nginx.conf`** (HTTPS, gzip, WebSocket, headers sécurité).

```bash
sudo cp deploy/nginx.conf /etc/nginx/sites-available/osint-ultimate
sudo nano /etc/nginx/sites-available/osint-ultimate   # remplacer osint.example.com
sudo ln -sf /etc/nginx/sites-available/osint-ultimate /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d votredomaine.io
```

## Sauvegardes

```bash
# Manuel
./scripts/backup.sh

# Automatique : Celery beat (tâche osint.backup_daily) si USE_CELERY_BEAT=true
```

Variables : `BACKUP_DIR`, `BACKUP_KEEP_DAYS` (voir `.env.example`).

## Gunicorn (variables)

| Variable | Défaut HF | VPS 4 vCPU |
|----------|-----------|------------|
| `GUNICORN_WORKERS` | 1 | 4–6 |
| `GUNICORN_TIMEOUT` | 120 | 120 |
| `GUNICORN_MAX_REQUESTS` | — | 1000 |

## Sécurité prod

- `SESSION_COOKIE_SECURE=true`
- `CORS_ORIGINS=https://votre-domaine.com`
- `SENTRY_DSN` pour les erreurs 500
- `WTF_CSRF_ENABLED=true` sur formulaires HTML

## Rollback

```bash
docker compose pull
docker compose up -d --no-build   # image tag précédente
```
