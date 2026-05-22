# Contribuer à OSINT Ultimate

## Ajouter un connecteur de recherche

1. Créer `connectors/mon_service.py` avec une fonction `search(target, options=None) -> dict`
2. Ajouter la fonction scan dans `app.py` : `def scan_mon_service(...): return connectors.mon_service.search(...)`
3. Enregistrer dans `SCAN_FUNCTIONS['mon_service'] = scan_mon_service`
4. Documenter la clé API dans `SECRETS.md`

## Migrations base de données

```bash
export FLASK_APP=app:app
flask db revision -m "description"
flask db upgrade
```

## Structure

- `connectors/` — sources externes
- `services/` — logique métier (corrélation, express, clés)
- `routes/` — blueprints Flask
- `migrations/` — Alembic

Voir `ROADMAP.md` pour les priorités.
