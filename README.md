---
title: OSINT Ultimate Backend
emoji: 🔍
colorFrom: blue
colorTo: gray
sdk: docker
app_port: 7860
pinned: false
---

# OSINT Ultimate V5.0

Plateforme OSINT (Flask) déployée sur [Hugging Face Spaces](https://huggingface.co/spaces/benji4565/osint_ultimate_backend), base PostgreSQL [Supabase](https://supabase.com/dashboard/project/mkciozumxpxllsjmcsyz).

Notes de version : **`RELEASE_V5.md`** · Feuille de route : **`ROADMAP.md`** · Secrets : **`SECRETS.md`**

## Aperçu visuel

Ajoutez vos captures dans `docs/images/` puis elles s'affichent ici :

| Express | Graphe | Expert |
|---------|--------|--------|
| ![Express](docs/images/express.png) | ![Graphe](docs/images/graph.png) | ![Expert](docs/images/expert.png) |

*(Placeholders — remplacer par de vraies captures pour la release GitHub.)*

## Parcours utilisateur

| URL | Public cible |
|-----|----------------|
| `/express` | Recherche type Google : un champ, détection auto du type, mobile-first |
| `/expert` | Console multi-modules, mode furtif, exports PDF/CSV/JSON |
| `/graph` | Graphe interactif : clic → analyse, PNG/SVG, légende |
| `/settings` | Clés API, proxies rotatifs, quotas, webhook |
| `/api/v1/docs` | Documentation OpenAPI |

## Secrets Hugging Face (Settings → Repository secrets)

| Secret | Obligatoire | Description |
|--------|-------------|-------------|
| `SECRET_KEY` | ✅ | Clé Flask (sessions/cookies). Générer : `python -c "import secrets; print(secrets.token_hex(32))"` |
| `DATABASE_URL` | ✅ | URI Supabase **Session mode** (port 5432). Ajouter `?sslmode=require` si absent |
| `GROQ_API_KEY` | ✅ | Clé API [Groq](https://console.groq.com/keys) pour le résumé IA |
| `FERNET_KEY` | ✅ | Chiffrement des clés API utilisateur. Générer : `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `SESSION_COOKIE_SECURE` | Recommandé | `true` sur HF (HTTPS) |
| `GROQ_MODEL` | Optionnel | Défaut : `llama-3.3-70b-versatile` |
| `HIBP_API_KEY` | Optionnel | Fuites email (Have I Been Pwned) |
| `SHODAN_API_KEY` | Optionnel | Enrichissement scan IP |
| `GITHUB_TOKEN` | Optionnel | Limite rate GitHub API |
| `NUMVERIFY_KEY` | Optionnel | Validation téléphone |
| `REDIS_URL` | Optionnel | Broker Celery (`redis://…`) pour file de tâches |
| `CACHE_TTL_*` | Optionnel | TTL cache par provider (ex. `CACHE_TTL_SHODAN=48`) |

### Où trouver `DATABASE_URL` sur Supabase

1. [Dashboard projet](https://supabase.com/dashboard/project/mkciozumxpxllsjmcsyz) → **Project Settings** → **Database**
2. Section **Connection string** → **URI** (mode Session, pas Transaction pooler pour les migrations)
3. Remplacer `[YOUR-PASSWORD]` par le mot de passe base
4. Coller dans HF Secrets (le code ajoute `sslmode=require` automatiquement)

## Migrations (automatiques au démarrage)

Au lancement du conteneur, `entrypoint.sh` exécute :

```bash
flask db upgrade
```

Schéma V4 : tables `user` et `scan` (historique, résumés IA en cache).

### Commandes locales (optionnel)

```bash
pip install -r requirements.txt
export FLASK_APP=app:app
export DATABASE_URL="postgresql://..."
flask db upgrade
python app.py
```

## Endpoints utiles

| Route | Description |
|-------|-------------|
| `/` | Interface principale |
| `/health` | Santé app + connexion DB |
| `/login` `/register` | Authentification |
| `/history` | Historique (connecté) |
| `/ai-summary` | Résumé IA (Groq) |

## Déploiement

```bash
git push huggingface main
```

Vérifier après build : `https://votre-space.hf.space/health` → `"database": "connected"`.

## Stack V5

- Flask 3 + SQLAlchemy + **Supabase PostgreSQL**
- Flask-Migrate (Alembic), cache API (`api_cache`)
- Flask-Login, Socket.IO, Groq IA, corrélation entités
- Celery + Redis (optionnel, scaffold `tasks.py`)
- Gunicorn + Gevent (port 7860)
