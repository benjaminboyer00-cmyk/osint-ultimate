# Performance & sécurité V6.4

## Déjà actif (code déployé)

| Domaine | Implémentation |
|---------|----------------|
| Compression | Flask-Compress (gzip) |
| Cache API | Redis + SQL + circuit breaker (`BaseConnector`) |
| Scans parallèles | `ThreadPoolExecutor` + sémaphores |
| Narratif async | Celery / thread + polling |
| Headers sécurité | flask-talisman (CSP, X-Frame-Options, Referrer-Policy) |
| Sentry | `SENTRY_DSN` optionnel |
| CSRF | Flask-WTF sur login/register/settings ; JSON exempt |
| Rate limit login | 10/min (login), 8/min (register) |
| Pagination entités | 25/page (graphe, carte, timeline) |
| Flask-Caching | Redis pour fragments (prêt à `@cache.cached`) |
| Docker VPS | `docker-compose.yml` + `docs/VPS_DEPLOY.md` |
| Gunicorn tuning | `GUNICORN_WORKERS`, `MAX_REQUESTS` via env |

## Secrets optionnels à ajouter

```
SENTRY_DSN=https://…@sentry.io/…
WTF_CSRF_ENABLED=true
GUNICORN_WORKERS=2
```

## Non fait (roadmap)

- Migration SPA (Vue/Alpine)
- Brotli (ajouter `brotli` + config Compress)
- 2FA TOTP
- Split complet des blueprints
- Minification assets build pipeline
- Locust test de charge
