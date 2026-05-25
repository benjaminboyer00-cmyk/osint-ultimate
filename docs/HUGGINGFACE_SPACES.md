# Hugging Face Spaces — WebSocket & scans Instagram

## Erreurs typiques dans la console navigateur

```text
socket.io … HTTP 400
GET /scan/67 HTTP 401
```

**401 sur `/scan/<id>`** : le frontend HF n’envoyait pas la session cookie (Spaces séparés).  
→ Corrigé : chaque `POST /scan` renvoie un **`poll_token`** ; le client appelle  
`GET /scan/67?poll_token=…` (avec `credentials: include`).

**400 sur socket.io** : le proxy Hugging Face casse Engine.IO.  
→ Corrigé : **Socket.IO désactivé** sur `*.hf.space` ; uniquement polling HTTP.

## Correctifs intégrés

| Composant | Comportement sur HF |
|-----------|---------------------|
| `static/js/socketio-client.js` | Socket.IO en **polling uniquement** sur `*.hf.space` |
| `index.html` | Polling de secours `/scan/<id>` toutes les 2,5 s |
| `entrypoint.sh` | `SPACE_ID` → 1 worker, timeout 300 s, **sans `--preload`**, `USE_CELERY=0` |
| `OSINT_IG_MODE=auto` | Instagram **sans instaloader** (HTTP léger) → évite OOM |
| `task_queue.py` | Pas de Celery sur HF sauf `OSINT_HF_CELERY=1` |

## Secrets HF recommandés

```bash
DATABASE_URL=postgresql://postgres.REF:…@aws-0-eu-west-1.pooler.supabase.com:5432/postgres?sslmode=require
SECRET_KEY=…
FERNET_KEY=…
GROQ_API_KEY=…
USE_CELERY=0
GUNICORN_TIMEOUT=300
# Instagram complet uniquement si Space Pro / assez de RAM :
# OSINT_IG_MODE=full
# IG_SESSION_FILE non utilisé sur HF sans volume session
```

## Instagram : HF vs VPS

| | Hugging Face (défaut) | VPS / Docker |
|--|----------------------|--------------|
| Mode | `OSINT_IG_MODE=auto` → HTTP | `full` ou `auto` → instaloader |
| Bio / compteurs | Souvent oui (HTML/API) | Oui |
| Posts / stories / à la une | Non (session requise) | Oui avec `session-ig` |

Pour **stories + highlights**, déployer le backend sur **VPS** avec `session-ig` monté (voir `docs/VPS_DEPLOY.md`).

## Vérifier les logs HF

Space → **Logs** : chercher `OOMKilled`, `Container restarted`, `Worker timeout`.

## Test après redéploiement

1. `GET /health` → `database: connected`
2. Scan Instagram → ne doit **plus** faire planter le Space (mode HTTP)
3. Console : plus d’erreur wss bloquante si le polling affiche le résultat
