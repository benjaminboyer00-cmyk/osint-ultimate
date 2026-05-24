# Checklist pré-VPS — état au 2026-05

## ✅ Fait dans le dépôt (code)

| Item | Fichier / action |
|------|------------------|
| Routes découpées | `routes/lookup`, `entity`, `reports`, `pages`, `ops`, `auth` |
| 2FA + zxcvbn | `routes/auth.py`, migration `012` |
| Handler erreurs global | `services/error_handlers.py` |
| Rate limits étendus | `app.py`, `routes/entity.py`, `api_v1.py` |
| Nginx prêt | `deploy/nginx.conf` |
| Docker compose prod | `docker-compose.yml` + volumes |
| CI/CD template | `.github/workflows/deploy.yml` |
| Lint + bandit + safety | `lint.yml`, `ci.yml` |
| Sauvegardes | `services/backup.py`, `tasks.py`, `scripts/backup.sh` |
| Cache HTTP statiques | `services/http_cache.py` |
| Tests IDOR + erreurs + E2E smoke | `tests/test_idor.py`, etc. |
| `.env.example` | complet |

## 🟡 À valider chez toi (4 actions bloquantes)

### 1. Docker local
```bash
chmod +x scripts/validate-docker.sh scripts/deploy.sh scripts/backup.sh
./scripts/validate-docker.sh
docker compose up -d
curl -s http://localhost:7860/health | python3 -m json.tool
```

### 2. Nginx sur le VPS
```bash
sudo cp deploy/nginx.conf /etc/nginx/sites-available/osint-ultimate
# Éditer server_name + SSL
sudo certbot --nginx -d votredomaine.io
```

### 3. CI/CD
Configurer les secrets : voir `docs/GITHUB_DEPLOY_SECRETS.md`  
Push sur `main` ou lancer le workflow manuellement.

### 4. Sentry
Ajouter `SENTRY_DSN` dans HF Secrets et `.env` VPS.

## Migration DB (Supabase — terminal dédié)

```bash
export DATABASE_URL="postgresql://..."   # Session pooler ou direct, voir dashboard Supabase
export FLASK_APP=app:app
flask db upgrade
flask db current   # → 012_pre_vps_security (head)
```

**Ne pas lancer `pytest` dans le même shell** juste après : les tests ignorent Supabase via `tests/conftest.py`, mais gardez deux terminaux pour plus de clarté.

## Tests (SQLite automatique)

```bash
unset DATABASE_URL    # optionnel
pytest tests/ -q
```

## Post-VPS (semaine 1+)

- Playwright E2E complet
- Dashboard métriques
- Stripe / légal
- Locust, minification assets, cache templates
