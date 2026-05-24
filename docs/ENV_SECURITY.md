# Sécurité du fichier `.env`

## Ne jamais pousser `.env`

- `.env` et `.env.*` sont dans `.gitignore` (sauf `.env.example`).
- Hook Git installé : `scripts/guard_env_git.sh` → `.git/hooks/pre-commit`
- Si `.env` a été commité par erreur : `git rm --cached .env` puis rotation de **toutes** les clés.

## Charger les variables en local

L’app charge automatiquement `.env` au démarrage (`config.py` + `python-dotenv`).

Vérifier les clés :

```bash
source .venv/bin/activate
python scripts/check_env.py
```

## Corriger `DATABASE_URL`

Sur IPv4 (PC, Hugging Face), utiliser le **pooler** dans `.env` :

```bash
export SUPABASE_DB_PASSWORD='…'
source scripts/export_supabase_env.sh pooler
# Copier la ligne dans .env :
# DATABASE_URL=postgresql://postgres.mkciozumxpxllsjmcsyz:…@aws-0-eu-west-1.pooler…
```

## Clés courantes

| Variable | Format attendu |
|----------|----------------|
| `GROQ_API_KEY` | `gsk_…` (console.groq.com) — pas une clé xAI |
| `SENTRY_DSN` | `https://…@o….ingest.sentry.io/…` |
| `REDIS_URL` | URL complète Redis Cloud (user + mot de passe) |
| `DEHASHED_*` | Email compte + clé API Dehashed |
