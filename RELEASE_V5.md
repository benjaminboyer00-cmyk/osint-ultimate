# OSINT Ultimate V5.0

## Nouveautés

### UX grand public
- **Express** (`/express`) : champ unique avec détection automatique email / téléphone / pseudo / domaine / IP — interface mobile-first.
- **Graphe** (`/graph`) : clic sur un nœud → lancement d'analyse, export PNG/SVG, légende des types.

### Reporting pro
- Export **PDF** horodaté (en-tête/pied de page, empreinte SHA-256).
- Export **CSV** et **JSON** depuis Expert et API v1.
- Option d'inclure une capture du graphe dans le PDF (POST `graph_png`).

### Architecture
- Cache TTL par connecteur (Hunter, Dehashed, Shodan, Wayback…) via `services/cache.py`.
- Scaffold **Celery + Redis** (`celery_app.py`, `tasks.py`) — actif si `REDIS_URL` est défini.
- Monitoring quotas API (Groq, Hunter) sur `/settings`.

### OPSEC
- Liste de proxies rotatifs dans les paramètres.
- Mode furtif global (settings) ou par scan (checkbox Expert).

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
