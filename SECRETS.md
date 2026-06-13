# Secrets & clés API — OSINT Ultimate

Configuration dans **Hugging Face Space → Settings → Repository secrets**  
Projet Supabase : voir note privée

## Obligatoires (production HF)

| Secret | Description | Comment l'obtenir |
|--------|-------------|-------------------|
| `SECRET_KEY` | Sessions Flask | `python -c "import secrets; print(secrets.token_hex(32))"` |
| `DATABASE_URL` | PostgreSQL Supabase (port **5432**, mode Session) | Supabase → Settings → Database → URI |
| `GROQ_API_KEY` | Résumé IA + assistant Express | https://console.groq.com/keys |
| `FERNET_KEY` | Chiffrement clés API par utilisateur | `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |

## Recommandés

| Secret | Description |
|--------|-------------|
| `SESSION_COOKIE_SECURE` | `true` sur HF |
| `GROQ_MODEL` | Optionnel — défaut `llama-3.3-70b-versatile` |

## Optionnels — enrichissement des scans

| Secret | Module impacté | Lien |
|--------|----------------|------|
| `SHODAN_API_KEY` | IP (ports, CVE, bannières) | https://account.shodan.io/ |
| `HIBP_API_KEY` | Email (fuites) | https://haveibeenpwned.com/API/Key |
| `GITHUB_TOKEN` | GitHub / pseudo | https://github.com/settings/tokens |
| `NUMVERIFY_KEY` | Téléphone | https://apilayer.com/ |
| `HUNTER_API_KEY` | Emails pro par domaine | https://hunter.io/api |
| `DEHASHED_API_KEY` | Fuites (avec `DEHASHED_EMAIL`) | https://dehashed.com/ |
| `DEHASHED_EMAIL` | Email compte Dehashed API | — |
| `EPIEOS_API_KEY` | Email / pseudo Epieos | https://epieos.com/ |
| `PROXY_LIST` | Tous (HTTP) | `http://proxy1:8080,http://proxy2:8080` |
| `REDIS_URL` | Cache + Celery | `rediss://…` (TLS Redis Cloud) |
| `SENTRY_DSN` | Monitoring erreurs 500 | https://sentry.io |
| `RATELIMIT_STORAGE_URI` | Rate limit partagé | même Redis, DB `/1` |
| `WTF_CSRF_ENABLED` | CSRF formulaires | `true` en prod |
| `GUNICORN_WORKERS` | VPS uniquement | `2`–`6` selon RAM |
| `CACHE_TTL_SHODAN` | TTL cache Shodan (heures) | ex. `24` |
| `CACHE_TTL_HUNTER` | TTL cache Hunter | ex. `48` |

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
