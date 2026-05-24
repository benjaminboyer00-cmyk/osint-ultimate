# Connexion Supabase — résoudre « password authentication failed »

## Symptôme

```
FATAL: password authentication failed for user "postgres"
```

## Cause la plus fréquente

Avec le **pooler Supavisor** (host `aws-0-eu-west-1.pooler.supabase.com`), l’utilisateur n’est **pas** `postgres` seul, mais :

```text
postgres.<PROJECT_REF>
```

Pour ton projet : **`postgres.mkciozumxpxllsjmcsyz`**

Si l’erreur cite `user "postgres"` (sans le suffixe projet), ton `DATABASE_URL` est incorrect.

## Format correct (Session mode — migrations Alembic)

Récupère la chaîne dans [Database Settings](https://supabase.com/dashboard/project/mkciozumxpxllsjmcsyz/settings/database) → **Connection string** → **URI** → mode **Session** (port **5432**).

Exemple (remplace `VOTRE_MOT_DE_PASSE`) :

```bash
export DATABASE_URL="postgresql://postgres.mkciozumxpxllsjmcsyz:VOTRE_MOT_DE_PASSE@aws-0-eu-west-1.pooler.supabase.com:5432/postgres?sslmode=require"
```

## IPv4 vs IPv6 (important)

| Mode | Host | User | Réseau |
|------|------|------|--------|
| **Session pooler** (recommandé HF / VPS / local IPv4) | `aws-0-eu-west-1.pooler.supabase.com:5432` | `postgres.mkciozumxpxllsjmcsyz` | IPv4 OK |
| **Direct** | `db.mkciozumxpxllsjmcsyz.supabase.co:5432` | `postgres` | Souvent **IPv6 seulement** (add-on IPv4 payant) |

Sur un PC ou Hugging Face en IPv4, utilisez le **pooler** — pas `postgres` seul sur le pooler (erreur *no tenant identifier*).

```bash
export DATABASE_URL="postgresql://postgres.mkciozumxpxllsjmcsyz:VOTRE_MDP@aws-0-eu-west-1.pooler.supabase.com:5432/postgres?sslmode=require"
```

## Connexion directe (IPv6 ou add-on IPv4)

```bash
export DATABASE_URL="postgresql://postgres:VOTRE_MOT_DE_PASSE@db.mkciozumxpxllsjmcsyz.supabase.co:5432/postgres?sslmode=require"
```

## Mot de passe avec caractères spéciaux

Si le mot de passe contient `@`, `#`, `%`, `/`, etc., encode-le en URL :

```bash
python3 -c "from urllib.parse import quote_plus; import getpass; print(quote_plus(getpass.getpass('Mot de passe DB: ')))"
```

Puis :

```text
postgresql://postgres.mkciozumxpxllsjmcsyz:ENCODED_PASSWORD@aws-0-eu-west-1.pooler...
```

## Vérifier la connexion

```bash
source .venv/bin/activate
export FLASK_APP=app:app
export DATABASE_URL="..."   # chaîne complète du dashboard
python scripts/check_database.py
```

Si OK :

```bash
flask db upgrade
flask db current
```

## Mot de passe réinitialisé ?

1. Supabase → **Project Settings** → **Database** → **Reset database password**
2. Mettre à jour `DATABASE_URL` en local, secrets **Hugging Face**, et futur `.env` VPS
3. Ne jamais commiter le mot de passe dans git

## Hugging Face

Le Space utilise le secret `DATABASE_URL` — il doit être **identique** à celui qui passe `check_database.py` en local.

## MCP Supabase dans Cursor

- Config : `.cursor/mcp.json` → serveur `supabase` (projet `mkciozumxpxllsjmcsyz`)
- **Redémarrer Cursor**, puis autoriser OAuth Supabase au premier appel MCP
- Option dashboard : **Read-only** + groupes de features limités
- Skills : `npx skills add supabase/agent-skills` → `.agents/skills/` (liens `.cursor/skills/`)
