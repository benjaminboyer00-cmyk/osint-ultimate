# Supabase — 3 étapes (connexion propre)

> **Sécurité :** ne commitez jamais le mot de passe. Changez-le si exposé dans un chat.

## Étape 1 — Mot de passe dans Supabase

1. [Database Settings](https://supabase.com/dashboard/project/mkciozumxpxllsjmcsyz/settings/database)
2. **Reset database password** → enregistrer
3. Copier le mot de passe (sans espace avant/après)

## Étape 2 — Exporter l’URL (choisir le mode)

```bash
cd ~/osint-ultimate
source .venv/bin/activate
export SUPABASE_DB_PASSWORD='VOTRE_MOT_DE_PASSE_ICI'
```

### Hugging Face / PC en IPv4 (recommandé)

```bash
source scripts/export_supabase_env.sh pooler
```

→ User : `postgres.mkciozumxpxllsjmcsyz`  
→ Host : `aws-0-eu-west-1.pooler.supabase.com`

### Direct (IPv6 uniquement chez Supabase)

```bash
source scripts/export_supabase_env.sh direct
```

Si erreur *Network is unreachable* → votre réseau est IPv4 : utilisez **pooler** (étape ci-dessus).

## Étape 3 — Vérifier + migration

```bash
python scripts/check_database.py
flask db upgrade
flask db current    # → 012_pre_vps_security (head)
```

## Secret Hugging Face

Collez **exactement** la valeur affichée après `source scripts/export_supabase_env.sh pooler` :

```bash
echo "$DATABASE_URL"
```

Copier dans HF → Settings → Secrets → `DATABASE_URL` → redémarrer le Space.

## pytest (ne touche pas Supabase)

```bash
pytest tests/ -q
```

Les tests utilisent SQLite en mémoire (`tests/conftest.py`), même si `DATABASE_URL` est exporté.
