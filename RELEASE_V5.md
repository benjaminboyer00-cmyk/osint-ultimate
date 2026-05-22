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

## Phase 7 V7 — Surveillance & alertes enrichies

- **`monitoring_alert`** + colonnes `alert_rules_json`, `last_snapshot_json` sur `scheduled_scan` (migration `010`).
- **Règles** : menace, fuite, WHOIS, sous-domaine, nouvelle section, erreur scan.
- **`services/monitor_snapshot.py`** : comparaison entre rescans.
- **Webhooks** Discord/Slack enrichis · **Email** optionnel (`ALERT_EMAIL_ENABLED` + SMTP).
- **Centre de notifications** : `GET /notifications`, cloche 🔔 dans l'Expert, Socket.IO `alert_notification`.
- Page **`/monitoring`** : choix des règles + historique des alertes.

## Phase 6 V7 — Timeline interactive (vis-timeline)

- **`services/timeline.py`** : `build_timeline()` — scans, WHOIS, Wayback, fuites, entités, liens.
- **`GET /timeline`** + **`GET /timeline/data/<entity_id>`** : frise vis-timeline par groupes.
- **`GET /api/v1/entity/<id>/timeline`** : export JSON API.
- **Socket.IO** : `join_timeline` + **`timeline_update`** après scan (racine `_root_entity_id`).
- Clic événement → graphe (`highlight`) + lien dossier / scan.
- Sources : dates Wayback, WHOIS, Dehashed, scans, création entités.

## Phase 5 V7 — Géolocalisation (Leaflet)

- **`services/geo.py`** : ip-api.com, cache 168h, persistance `entity.latitude/longitude`.
- **`GET /map`** + **`GET /map/data/<entity_id>`** : carte Leaflet + MarkerCluster.
- **`GET /api/v1/entity/<id>/map`** : marqueurs JSON pour l'API.
- **Socket.IO** : `join_map` + événement **`map_update`** après scan (si `_root_entity_id`).
- **Graphe** : lien carte, paramètre `?highlight=<entity_id>` depuis la carte.
- Migration **`009_v7_entity_geo`**.

## Phase 4 V7 — Livrable blindé

- **`scan.report_pdf_hash`** + **`report_sealed_at`** (migration `008_v7_report_seal`).
- **`services/report_seal.py`** : QR code, scellement PDF, vérification upload.
- **Page de garde PDF** : empreintes SHA-256, QR vers `/verify/<scan_id>`.
- **`GET/POST /verify/<scan_id>`** : upload PDF public → ✅ authentique / ❌ modifié.
- **Traçabilité** : colonne **Statut** (succès, cache, fallback, timeout, erreur).
- Export PDF **double passe** : empreinte fichier inscrite dans le document final.
- Dépendance **`qrcode[pil]`**.

## Phase 3 V7 — Rapport narratif IA

- **`services/report_data.py`** : `build_report_data(entity_id)` — entités, liens, scans, sources.
- **`services/groq.py`** : `generate_narrative_report()` (Markdown structuré), `markdown_to_html()`.
- **`services/narrative_report.py`** : orchestration + PDF dossier.
- **Dossier** : boutons « Générer le texte » et « PDF narratif » (`POST /expert/dossier/<id>/narrative`, `GET …/narrative/pdf`).
- **`report_pro.html`** : section « Rapport d'enquête narratif (IA) ».
- Dépendance **`markdown2`** pour WeasyPrint.

## Phase 2 V7 — Pivot graphe

- **`services/graph_pivot.py`** : modules par type d'entité, `launch_pivot`, `graph_update` Socket.IO.
- **`POST /graph/pivot`** et **`POST /api/v1/graph/pivot`**.
- **`graph.html`** : menu contextuel (clic droit) → Pivoter, Analyser, Dossier, Copier.
- Fusion dynamique des nœuds/arêtes après scan (`graph_update`).
- **pypdf** remplace PyPDF2 (plus d'avertissement pytest).

## Phase 1 V7 — Dorking avancé

- **`connectors/dorking.py`** : `DorkingConnector` (dorks LinkedIn, Twitter, GitHub, documents, emails).
- Moteur **DuckDuckGo HTML** + cache 12h ; extraction profils/URLs/emails.
- Expert : case **« Recherche profonde (Dorking) »** + module **🔎 Dorking**.
- Multi-scan : ajout automatique du module si `deep_dorking=true`.

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
