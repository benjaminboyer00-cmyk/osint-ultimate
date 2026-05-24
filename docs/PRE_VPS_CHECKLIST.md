# Checklist pré-VPS (code livré)

## Fait dans le dépôt

- [x] Routes découpées : `lookup`, `entity`, `reports`, `pages`, `ops`, `auth`
- [x] `.env.example` complet (Redis, Sentry, CSRF, Gunicorn, compression)
- [x] `docker-compose.yml` : volumes uploads/logs, `GUNICORN_WORKERS`, image registry
- [x] `scripts/deploy.sh` + workflow `.github/workflows/deploy.yml`
- [x] Lint CI : black, isort, flake8, bandit
- [x] 2FA TOTP (`pyotp`, migration `012_pre_vps_security`)
- [x] Politique mot de passe (`zxcvbn`)
- [x] Exceptions `ConnectorError` / `APIQuotaExceeded`
- [x] Brotli + gzip (`COMPRESS_ALGORITHM`)
- [x] `/health` : ping Celery, `Cache-Control`
- [x] Tests smoke E2E + `test_pre_vps.py`

## À faire sur le VPS (hors code)

1. Ubuntu 22.04, Docker, ufw (22/80/443), fail2ban
2. Domaine + DNS A → IP VPS
3. Traefik ou Nginx + Let's Encrypt
4. Copier `.env` (jamais dans git), `docker compose up -d`
5. Secrets GitHub : `VPS_HOST`, `VPS_USER`, `VPS_SSH_KEY`, `VPS_APP_DIR`
6. Sauvegardes Supabase + volume `uploads_data`

## Migration base (2FA + index)

Sur HF ou VPS après déploiement :

```bash
flask db upgrade
# ou via Docker :
docker compose exec web flask db upgrade
```

Révision Alembic : `012_pre_vps_security` (colonnes `totp_*`, index `scan` / `entity`).

## Commandes locales avant migration

```bash
cp .env.example .env   # puis éditer
docker compose build
docker compose up -d
docker compose exec web flask db upgrade
curl -s http://localhost:7860/health | jq .
python -m pytest tests/ -q
```
