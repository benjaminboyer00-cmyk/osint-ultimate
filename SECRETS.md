# Secrets & clés API — OSINT Ultimate

Configuration dans **Hugging Face Space → Settings → Repository secrets**  
Projet Supabase : https://supabase.com/dashboard/project/mkciozumxpxllsjmcsyz

## Obligatoires (production HF)

| Secret | Description | Comment l'obtenir |
|--------|-------------|-------------------|
| `SECRET_KEY` | Sessions Flask | `python -c "import secrets; print(secrets.token_hex(32))"` |
| `DATABASE_URL` | PostgreSQL Supabase (port **5432**, mode Session) | Supabase → Settings → Database → URI |
| `OPENROUTER_KEY` | Résumé IA + assistant Express | https://openrouter.ai/keys |
| `FERNET_KEY` | Chiffrement clés API par utilisateur | `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |

## Recommandés

| Secret | Description |
|--------|-------------|
| `SESSION_COOKIE_SECURE` | `true` sur HF |
| `OPENROUTER_REFERER` | URL du Space HF |
| `OPENROUTER_MODEL` | Modèle forcé si erreur « Provider returned error » — essayer `google/gemma-2-9b-it:free` |

## Optionnels — enrichissement des scans

| Secret | Module impacté | Lien |
|--------|----------------|------|
| `SHODAN_API_KEY` | IP (ports, CVE, bannières) | https://account.shodan.io/ |
| `HIBP_API_KEY` | Email (fuites) | https://haveibeenpwned.com/API/Key |
| `GITHUB_TOKEN` | GitHub / pseudo | https://github.com/settings/tokens |
| `NUMVERIFY_KEY` | Téléphone | https://apilayer.com/ |
| `HUNTER_API_KEY` | Email pro (domaine) — *Phase 4* | https://hunter.io/api |
| `DEHASHED_API_KEY` | Fuites — *Phase 4* | https://dehashed.com/ |
| `PROXY_LIST` | Tous (HTTP) | `http://proxy1:8080,http://proxy2:8080` |

## Clés par utilisateur (interface `/settings`)

Une fois connecté, l'utilisateur peut saisir **ses propres** clés (stockées chiffrées avec `FERNET_KEY`) :

- Shodan, HIBP, Hunter, Numverify, GitHub

Priorité : secret global HF → clé utilisateur → module désactivé.

## Clé API REST (Expert)

Générée dans **Paramètres → Clé API REST**.  
Header : `X-API-Key: <token>`

## Vérification post-déploiement

1. `GET /health` → `"database": "connected"`
2. Inscription + login
3. Express : recherche téléphone
4. Expert : scan IP avec Shodan (si clé)
5. `GET /api/docs` → schéma OpenAPI
