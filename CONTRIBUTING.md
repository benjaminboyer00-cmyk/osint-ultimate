# Contribuer à OSINT Ultimate

## Ajouter un connecteur (modèle officiel)

1. Créer `connectors/mon_service.py` :

```python
def search(target: str, api_key: str, options=None) -> dict:
    """Retourne un dict {section: valeur} — jamais d'exception non gérée."""
    if not api_key:
        return {'Erreur': 'Clé API non configurée'}
    # … appel API + cache via services.cache
    return {'Résultats': [...]}
```

2. Ajouter dans `scan_modules.py` :

```python
def scan_mon_service(target, options=None):
    key = _opt(options, '_mon_key', 'MON_API_KEY')
    from connectors.mon_service import search
    return search(target, key, options)

EXTRA_SCAN_FUNCTIONS['mon_service'] = scan_mon_service
```

3. Enregistrer les règles de corrélation dans `services/correlation.py` si pertinent.

4. Documenter la clé dans `SECRETS.md` et le champ dans `templates/settings.html`.

5. Ajouter un test dans `tests/`.

## Structure du dépôt

| Dossier | Rôle |
|---------|------|
| `connectors/` | Sources externes (Hunter, Dehashed, …) |
| `services/` | Métier : corrélation, cache, IA, webhooks |
| `routes/` | Blueprints Flask (views, API v1) |
| `scan_modules.py` | Enregistrement modules scan V5 |
| `migrations/` | Alembic / Supabase |

## Migrations

```bash
export FLASK_APP=app:app
flask db upgrade
```

## Tests locaux

```bash
pip install -r requirements.txt pytest
pytest tests/ -v
```

## Checklist PR

- [ ] Connecteur avec gestion d'erreur et cache TTL
- [ ] Pas de secret en dur
- [ ] SECRETS.md mis à jour
- [ ] ROADMAP.md statut mis à jour
