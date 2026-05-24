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

## Nginx (extrait)

```nginx
server {
    listen 443 ssl http2;
    server_name osint.example.com;

    ssl_certificate /etc/letsencrypt/live/osint.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/osint.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:7860;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /socket.io/ {
        proxy_pass http://127.0.0.1:7860/socket.io/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

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
