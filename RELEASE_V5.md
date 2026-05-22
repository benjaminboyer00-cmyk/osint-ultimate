# OSINT Ultimate V5.0

## Nouveautés

### UX grand public
- **Express** (`/express`) : champ unique avec détection automatique email / téléphone / pseudo / domaine / IP — interface mobile-first.
- **Graphe** (`/graph`) : clic sur un nœud → lancement d'analyse, export PNG/SVG, légende des types.

### Reporting pro
- Export **PDF** horodaté avec en-tête/pied de page professionnels.
- **Signature numérique** : empreinte SHA-256 du contenu + signature du document (bloc dédié dans le PDF).
- Capture du **graphe de corrélation** via POST `graph_png` (depuis `/graph` → export PNG).
- Export **CSV** et **JSON** depuis Expert et API v1.

### Surveillance continue
- Page **`/monitoring`** : liste des surveillances, fréquences quotidien / hebdomadaire.
- Mode Expert : case **« Surveiller cette cible »** + API `POST /monitoring/quick`.
- Moteur APScheduler (5 min) ; compatible scaffold Celery (`REDIS_URL`).

### Architecture
- Cache TTL par connecteur (Hunter, Dehashed, Shodan, Wayback…) via `services/cache.py`.
- Scaffold **Celery + Redis** (`celery_app.py`, `tasks.py`) — actif si `REDIS_URL` est défini.
- Monitoring quotas API (Groq, Hunter) sur `/settings`.

### OPSEC
- Liste de proxies rotatifs dans les paramètres.
- Mode furtif global (settings) ou par scan (checkbox Expert).

## Phase 10 — Celery + Redis (V5.2)

- **`services/task_queue.py`** : si `REDIS_URL` + `USE_CELERY=auto`, les scans passent par `osint.run_scan` (Celery) au lieu du thread.
- **`tasks.py`** : réutilise `process_scan_by_id` (même logique, polling client).
- **Beat** : tâche `osint.scheduled_tick` toutes les 5 min — activer avec `USE_CELERY_BEAT=true` + `scripts/run_celery_beat.sh`.
- Scripts : `scripts/run_celery_worker.sh`.

```bash
export REDIS_URL=redis://localhost:6379/0
./scripts/run_celery_worker.sh
# optionnel surveillance :
USE_CELERY_BEAT=true ./scripts/run_celery_beat.sh
```

## Fallback scraping (quota API) — V5.2

- **Hunter / Dehashed** : si 429/quota ou réponse vide (Hunter), bascule sur `connectors/scraper_fallback.py` (DuckDuckGo HTML, BeautifulSoup).
- Métadonnées : `_source: scraping_fallback`, `_degraded: true` + bannière orange Expert/Express.
- Timeouts multi-scan : **20 s** / module, **60 s** global.
- **`cloudscraper`** dans `requirements.txt` — pages Cloudflare (`fetch_url_protected`, module `site`).
- **Paramètres → OPSEC** : case « Fallback scraping » (`user.scrape_fallback_enabled`, migration 007).
- Env : `SCRAPE_FALLBACK_ENABLED`, `CLOUDSCRAPER_ENABLED` (désactivation globale admin).

## Phase 8 — Recettes & marketplace (V5.2)

- **`/recipes`** : 6 recettes officielles + création / partage communautaire + lancement scan multi.
- **`/marketplace`** : catalogue connecteurs (statut, catégorie, clé API requise).
- API : `GET/POST /api/v1/recipes`, `POST /api/v1/recipes/{id}/run`, `GET /api/v1/connectors`.
- Migration `006_v7_recipes` (table `recipe`).

## Phase 9 — Menace & alertes (V5.2)

- Connecteurs **OTX** (`connectors/otx.py`) et **URLhaus** (`connectors/urlhaus.py`).
- Recette builtin **Menace — IOC check**.
- **Alertes surveillance** : `notify_on_change` + webhook `monitoring.alert` (hausse menace, erreurs scan).

## Phase 7 — Rapport de preuve (V5.1)

- Template **`report_pro.html`** : page de garde, résumé exécutif, méthodologie, chaîne de traçabilité, annexe données, certificat d'intégrité, mentions légales.
- **`services/report_builder.py`** : extraction sources/modules/horodatages depuis le scan.
- **`services/report_export.py`** : export unifié (UI `/report/{id}` + API `GET /api/v1/export/{id}/pdf`).
- En-têtes HTTP : `X-Document-Hash`, `X-Content-Hash`, `X-Signature-Hash`, `X-Scan-Id`.
- **`GET /report/{id}/verify?hash=…`** : vérification d'intégrité côté session.
- **`/privacy`** enrichi : journal des traitements, droits RGPD, suppression, vérification PDF.

## Phase 6 — Enquête guidée & scoring (V5.1)

- **Agent IA** (`/investigate`) : planification Groq + exécution séquentielle des modules, timeline Socket.IO.
- **Scoring graphe** : confiance sur les liens (`entity_link.confidence`), épaisseur des arêtes, **Mode Enquête** (suggestion du prochain nœud).
- API : `POST /api/v1/investigate`, `GET /api/v1/entity/{id}/suggestions`.

## Correctifs post-release

- **Cache** : `ApiCache` possède une colonne `query` qui masquait `Model.query` — le cache utilise `db.session.query(ApiCache)`.
- **Express → Expert** : les suggestions IA pointent vers `/expert?module=…&target=…` avec lancement auto du scan.

## Migration depuis V4.2

```bash
flask db upgrade
```

Secrets HF inchangés + optionnels : `REDIS_URL`, `CACHE_TTL_SHODAN`, `CACHE_TTL_HUNTER`, etc.

## Release GitHub

```bash
git tag -a v5.0.0 -m "OSINT Ultimate V5.0"
git push origin v5.0.0
gh release create v5.0.0 --title "OSINT Ultimate V5.0" --notes-file RELEASE_V5.md
```
