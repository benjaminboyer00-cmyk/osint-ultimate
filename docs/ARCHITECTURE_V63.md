# Architecture V6.3 — Scalabilité (guide opérateur)

Ce document décrit ce qui a été ajouté dans le code et **ce que vous devez configurer** sur Hugging Face / Supabase.

## Déjà en place dans le code

| Composant | Fichier | Comportement |
|-----------|---------|--------------|
| Scans parallèles Express/Expert | `services/scanner.py` | `ThreadPoolExecutor` + sémaphores par API (Hunter, dorking…) |
| File Celery (optionnelle) | `services/task_queue.py`, `tasks.py` | Si `REDIS_URL` → scans + narratif en worker |
| Cache Redis (optionnel) | `services/cache_manager.py` | TTL par provider ; repli SQL `ApiCache` |
| Narratif asynchrone | `services/async_tasks.py` | `POST` avec `"async": true` → `task_id` + polling |
| HTTP furtif | `services/http_session.py` | Rotation UA, proxies, blacklist proxies morts |
| Request ID | `services/request_log.py` | Header `X-Request-ID` dans les logs |
| Suggestions dossier | `GET /expert/dossier/<id>/suggestions` | Modules non encore lancés |
| Health détaillé | `GET /health` | DB, Redis, Groq, imports modules |

## Ce que vous devez faire

### 1. Secrets Hugging Face (Settings → Variables)

| Variable | Obligatoire | Description |
|----------|-------------|-------------|
| `SECRET_KEY` | Oui (prod) | Clé Flask aléatoire longue |
| `DATABASE_URL` | Oui | URL Supabase PostgreSQL |
| `GROQ_API_KEY` | Pour l’IA | API Groq |
| `FERNET_KEY` | Recommandé | Chiffrement clés API utilisateur |
| `REDIS_URL` | Recommandé | `redis://...` (Redis Cloud gratuit ~30 Mo) |
| `CORS_ORIGINS` | Optionnel | `https://votre-space.hf.space` (pas `*` en prod stricte) |
| `PROXY_LIST` | Optionnel | `http://proxy1:8080,http://proxy2:8080` |
| `RATELIMIT_STORAGE_URI` | Optionnel | `redis://...` si plusieurs workers Gunicorn |

### 2. Activer Redis + Celery (recommandé prod)

1. Créer une instance [Redis Cloud](https://redis.com/try-free/) (ou Upstash).
2. Copier l’URL dans `REDIS_URL` sur le Space HF.
3. Redémarrer le Space → `/health` doit afficher `"redis_cache": "connected"` et `"celery": "enabled"`.

Sans Redis : tout fonctionne en **threads** (comportement historique), mais le cache n’est pas partagé entre workers Gunicorn.

### 3. Worker Celery sur HF (même conteneur, option avancée)

Dans `README` ou script de démarrage du Space, vous pouvez lancer en parallèle :

```bash
celery -A celery_app.celery_app worker --loglevel=info --concurrency=1 &
gunicorn ...
```

Attention à la RAM (16 Go max sur Space gratuit). Sinon gardez le mode thread (`USE_CELERY=0`).

### 4. Vérifications après déploiement

```bash
curl https://VOTRE-SPACE.hf.space/health
```

- `"modules"."services.report_consolidate": "ok"`
- `"redis_cache": "connected"` (si Redis configuré)

Test narratif async (connecté) :

```http
POST /expert/dossier/25/narrative
{"style":"executive","length":"medium","async":true}
→ 202 { "task_id", "poll_url" }

GET /expert/dossier/25/narrative/status/<task_id>
→ 202 pending | 200 completed + markdown
```

### 5. Monitoring gratuit

- [UptimeRobot](https://uptimerobot.com) → ping `/health` toutes les 5 min.
- Logs HF : filtrer `ERROR` et `request_id` (header `X-Request-ID`).

### 6. Non fait volontairement (roadmap)

- Migration complète **Quart/FastAPI** : gros chantier ; le parallélisme threads couvre déjà Express/Expert.
- **fake-useragent** : optionnel (`pip install fake-useragent`) ; repli sur liste UA intégrée.
- **CSRF Flask-WTF** : à activer sur formulaires HTML login/settings si vous exposez l’app hors HF auth.
- Split complet des blueprints : partiel (api_v1, collaboration, views).

## Index Supabase suggérés

```sql
CREATE INDEX IF NOT EXISTS idx_scan_user_root ON scan(user_id, root_entity_id);
CREATE INDEX IF NOT EXISTS idx_entity_user_type_value ON entity(user_id, entity_type, value);
CREATE INDEX IF NOT EXISTS idx_apicache_key ON api_cache(cache_key);
```
