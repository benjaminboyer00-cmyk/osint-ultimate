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

Plateforme OSINT (Flask) déployée sur [Hugging Face Spaces](https://huggingface.co/spaces/benji4565/osint_ultimate_backend), base PostgreSQL Supabase (voir note privée pour l'accès au projet).

Notes de version : **`RELEASE_V5.md`** · Feuille de route : **`ROADMAP.md`** · Secrets : **`SECRETS.md`** · Collaboration V8 : **`docs/COLLABORATION_V8.md`**

## Fonctionnalités V5

### Mode Express (`/express`)
- Champ unique avec **détection automatique** du type (email, téléphone, site, IP, pseudo).
- Carte de synthèse lisible + assistant IA Groq (« Comprendre »).
- Actions IA qui ouvrent **directement le bon scan en mode Expert** (`/expert?module=…&target=…`).
- Interface **mobile-first**, sans grille de modules.

### Mode Expert (`/expert`)
- Console **19+ modules** : Sherlock, Hunter, Dehashed, Epieos, Shodan, WHOIS, Wayback, réseaux sociaux, etc.
- **Mode furtif** (User-Agent aléatoire, délais, proxies rotatifs depuis `/settings`).
- Exports **PDF** (horodaté, empreinte SHA-256), **CSV**, **JSON**.
- Analyse de fichiers (EXIF, PDF, DOCX).

### Graphe unifié & analyse IA (V6)
- **Graphe rapide** : chargement en 2 requêtes (bulk-load) au lieu de N+1 — fin des lenteurs sur les cibles riches.
- **Unification d'entités** (« même personne ») : regroupe plusieurs identifiants d'un individu (ex. `benji` = `benjamin.boyer00`) via menu contextuel ou suggestions. Réversible, sans migration.
- **Analyse IA** `🧠` : incohérences, hypothèses de liens et **pistes d'investigation priorisées** (pas un simple résumé).
- **Comparaison de graphes** `⇄` : recouvrement d'identifiants + verdict IA (même personne / liés / distincts).
- **IA multi-fournisseur** : bascule automatique Groq → Gemini → Cerebras → OpenRouter (tiers gratuits) + cache — robustesse même en cas de rate-limit.

### Corrélation & API
- **Graphe** `/graph` : Cytoscape, clic → nouveau scan, export PNG/SVG, légende.
- **API REST** `/api/v1` : search, export, scans programmés, webhooks, OpenAPI.
- **Cache** TTL par connecteur (Hunter, Dehashed, Shodan…) — table `api_cache`.
- **Celery** (optionnel) si `REDIS_URL` est défini.

## Parcours utilisateur

| URL | Public cible |
|-----|----------------|
| `/express` | Recherche type Google : un champ, détection auto du type, mobile-first |
| `/expert` | Console multi-modules, mode furtif, exports PDF/CSV/JSON |
| `/graph` | Graphe interactif : clic → analyse, PNG/SVG, légende |
| `/monitoring` | Surveillance continue (quotidien / hebdomadaire) |
| `/settings` | Clés API, proxies rotatifs, quotas, webhook |
| `/api/v1/docs` | Documentation OpenAPI |

## Secrets Hugging Face (Settings → Repository secrets)

| Secret | Obligatoire | Description |
|--------|-------------|-------------|
| `SECRET_KEY` | ✅ | Clé Flask (sessions/cookies). Générer : `python -c "import secrets; print(secrets.token_hex(32))"` |
| `DATABASE_URL` | ✅ | URI Supabase **Session mode** (port 5432). Ajouter `?sslmode=require` si absent |
| `GROQ_API_KEY` | ✅ | Clé API [Groq](https://console.groq.com/keys) pour l'IA (fournisseur principal) |
| `FERNET_KEY` | ✅ | Chiffrement des clés API utilisateur. Générer : `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `SESSION_COOKIE_SECURE` | Recommandé | `true` sur HF (HTTPS) |
| `GROQ_MODEL` | Optionnel | Défaut : `llama-3.3-70b-versatile` |
| `GEMINI_API_KEY` | Optionnel | Secours IA — Google AI Studio (Flash gratuit ~1500 req/j) |
| `CEREBRAS_API_KEY` | Optionnel | Secours IA — inference gratuite rapide |
| `OPENROUTER_API_KEY` | Optionnel | Secours IA — modèles `:free` (dernier recours) |
| `LLM_PROVIDER_ORDER` | Optionnel | Ordre de bascule, ex. `groq,gemini,cerebras` |
| `LLM_CACHE_TTL` | Optionnel | Cache réponses IA en secondes (défaut 900) |
| `HIBP_API_KEY` | Optionnel | Fuites email (Have I Been Pwned) |
| `SHODAN_API_KEY` | Optionnel | Enrichissement scan IP |
| `GITHUB_TOKEN` | Optionnel | Limite rate GitHub API |
| `NUMVERIFY_KEY` | Optionnel | Validation téléphone |
| `REDIS_URL` | Optionnel | Broker Celery (`redis://…`) pour file de tâches |
| `CACHE_TTL_*` | Optionnel | TTL cache par provider (ex. `CACHE_TTL_SHODAN=48`) |

### Où trouver `DATABASE_URL` sur Supabase

1. Dashboard projet Supabase (voir note privée) → **Project Settings** → **Database**
2. Section **Connection string** → **URI** (mode Session, pas Transaction pooler pour les migrations)
3. Remplacer `[YOUR-PASSWORD]` par le mot de passe base
4. Coller dans HF Secrets (le code ajoute `sslmode=require` automatiquement)

## Migrations (automatiques au démarrage)

Au lancement du conteneur, `entrypoint.sh` exécute :

```bash
flask db upgrade
```

Schéma V4+ : tables `user` et `scan` (historique, résumés IA en cache).  
**V8** : `dossier_collaborator`, `entity_comment`, `dossier_activity_log`, `collaboration_notification`, `scan.root_entity_id` (révision `011_v8_collaboration`).

### Commandes locales (optionnel)

Sur Ubuntu/Debian récent, préférez un **venv** (évite `ModuleNotFoundError: whois`) :

```bash
./scripts/setup_dev.sh
source .venv/bin/activate
export FLASK_APP=app:app
export DATABASE_URL="postgresql://..."
flask db upgrade
python app.py
```

Ou manuellement : `pip install -r requirements.txt` (le paquet `python-whois` fournit `import whois`).

Tests : depuis la racine du dépôt, `python -m pytest tests/ -q` (ou `pytest` si `pytest.ini` est lu).

## Endpoints utiles

| Route | Description |
|-------|-------------|
| `/` | Interface principale |
| `/health` | Santé app + connexion DB |
| `/login` `/register` | Authentification (`auth` blueprint) |
| `/settings/security` | 2FA TOTP |
| `/history` | Historique (connecté) |
| `/invitations` | Invitations collaboration (V8) |
| `/dossier/<entity_id>` | Dossier partagé (activité, collaborateurs) |

### Collaboration (V8)

1. Ouvrir un dossier depuis le graphe ou `/expert/dossier/<entity_id>`.
2. **Partager** (rôle admin) : saisir l'email d'un utilisateur **déjà inscrit**, créer l'invitation, **copier le lien** affiché.
3. L'invité se connecte, ouvre le lien → `/invitations` → **Accepter**.
4. Rôle **éditeur** : peut lancer des scans visibles dans le dossier du propriétaire.

Détails : `docs/COLLABORATION_V8.md`.

| `/ai-summary` | Résumé IA (Groq) |

## Déploiement Hugging Face

```bash
git push huggingface main
```

Vérifier après build : `https://votre-space.hf.space/health` → `"database": "connected"`.

## Déploiement VPS (préparation)

Checklist complète : **`docs/PRE_VPS_CHECKLIST.md`**

| Fichier | Rôle |
|---------|------|
| `docker-compose.yml` | web + worker + beat + redis |
| `deploy/nginx.conf` | Reverse proxy HTTPS |
| `scripts/deploy.sh` | Déploiement depuis GHCR |
| `scripts/validate-docker.sh` | Test build local |
| `docs/GITHUB_DEPLOY_SECRETS.md` | Secrets CI/CD |

Secrets recommandés : `SENTRY_DSN`, `WTF_CSRF_ENABLED=true`, `FORCE_HTTPS=true` (VPS).

## Stack V5

- Flask 3 + SQLAlchemy + **Supabase PostgreSQL**
- Compression **brotli + gzip** (Flask-Compress)
- **2FA TOTP**, politique mots de passe **zxcvbn**
- Rate limiting API (`/api/v1/search`, export PDF, pivot) — 10–30 req/min par clé
- Flask-Migrate (Alembic), cache API (`api_cache`)
- Flask-Login, Socket.IO, Groq IA, corrélation entités
- Celery + Redis (optionnel, scaffold `tasks.py`)
- Gunicorn + Gevent (port 7860)
