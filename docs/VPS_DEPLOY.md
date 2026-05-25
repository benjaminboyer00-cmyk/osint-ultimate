# Déploiement VPS (Nginx + Docker)

## Prérequis

- Domaine + DNS vers le VPS
- Docker + docker-compose
- Variables dans `.env` (copier depuis `SECRETS.md`)

## Démarrage local (stack complète)

```bash
cp .env.example .env   # si présent, sinon créer .env
# Dev : expose Redis + port public
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
curl http://127.0.0.1:7860/health
```

**Production VPS** (Redis non exposé, app sur localhost uniquement) :

```bash
docker compose up -d --build
# Nginx proxy vers 127.0.0.1:7860
```

## Nginx

Fichier complet prêt à l’emploi : **`deploy/nginx.conf`** (HTTPS, gzip, WebSocket, headers sécurité).

```bash
sudo cp deploy/nginx.conf /etc/nginx/sites-available/osint-ultimate
sudo nano /etc/nginx/sites-available/osint-ultimate   # remplacer osint.example.com
sudo ln -sf /etc/nginx/sites-available/osint-ultimate /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo DOMAIN=votredomaine.io EMAIL=admin@votredomaine.io ./scripts/certbot-setup.sh
# ou : RUN_CERTBOT=1 DOMAIN=votredomaine.io sudo ./scripts/deploy.sh latest
```

### Timeouts Nginx

`deploy/nginx.conf` définit `proxy_read_timeout` / `proxy_send_timeout` à **120s** (évite les 504 sur scans longs). WebSocket : **300s** sur `/socket.io/`.

### Logs Docker (rotation disque)

`docker-compose.yml` limite chaque service à **3×10 Mo** (`json-file` max-size / max-file).

### Rétention données

Celery beat exécute **`osint.data_retention`** chaque **dimanche 03:00 UTC** :
- fichiers `uploads/` > 30 jours (`RETENTION_UPLOAD_DAYS`)
- lignes `api_cache` expirées

### Healthchecks

Redis / web / worker ont des `healthcheck` Docker — redémarrage auto si worker zombie (`restart: unless-stopped`).

## Session Instagram (Docker)

Sans montage du fichier de session, le worker refait `login()` à chaque scan → risque de blocage du compte chaussette.

1. **Une fois sur l’hôte** (pas dans le conteneur).

   **Méthode A — Firefox** (recommandée si `login` instaloader échoue avec `fail`) :
   ```bash
   # 1) Se connecter à instagram.com dans Firefox (Snap sous Ubuntu = profil séparé)
   # 2) Fermer Firefox, puis :
   source .venv/bin/activate
   python scripts/import_ig_session_firefox.py --list   # voir quel profil a des cookies
   python scripts/import_ig_session_firefox.py
   ```
   Sous Ubuntu Snap, les cookies sont souvent dans
   `~/snap/firefox/common/.mozilla/firefox/` (pas `~/.mozilla/`).

   **Méthode A2 — cookies.txt** (extension « Get cookies.txt LOCALLY ») :
   ```bash
   python scripts/import_ig_session_cookies_txt.py ~/Downloads/cookies.txt
   ```

   **Méthode B — mot de passe** :
   ```bash
   export IG_DUMMY_USER=votre_compte
   export IG_DUMMY_PASS="mot_de_passe"   # guillemets doubles si apostrophe
   python scripts/create_ig_session.py
   ```
   → crée `./session-ig` (ignoré par git).

2. **`.env` sur le VPS** :
   ```bash
   IG_SESSION_FILE=/code/session-ig
   IG_DUMMY_USER=votre_compte
   # IG_DUMMY_PASS peut rester vide si la session suffit
   ```

3. **`docker-compose.yml`** monte déjà `./session-ig:/code/session-ig:ro` sur `web` et `worker`.

4. Redémarrer : `docker compose up -d`

> Si `./session-ig` n’existe pas au premier `docker compose up`, Docker peut créer un **dossier** vide — générez le fichier **avant** le premier déploiement.

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
