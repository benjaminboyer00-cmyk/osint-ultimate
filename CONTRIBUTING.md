# Contribuer à OSINT Ultimate

Merci de votre intérêt pour le projet. Ce guide décrit comment ajouter un connecteur, proposer une correction ou préparer une pull request.

## Prérequis

```bash
git clone <votre-fork>
cd osint-ultimate
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export FLASK_APP=app:app
export DATABASE_URL="sqlite:///osint.db"   # ou Supabase en prod
flask db upgrade
python app.py
```

## Ajouter un connecteur en 5 étapes

### Étape 1 — Créer le fichier connecteur

Créez `connectors/mon_service.py` :

```python
"""Mon Service — description courte."""
from services.cache import get_cached, set_cached, get_ttl_hours
from services.http_client import safe_get


def search(target: str, api_key: str, options=None) -> dict:
    """
    Retourne un dict {section: valeur}.
    Ne jamais laisser remonter une exception non gérée.
    """
    if not api_key:
        return {'Erreur': 'Clé API non configurée (MON_API_KEY ou /settings)'}

    target = (target or '').strip()
    cached = get_cached('mon_service', target)
    if cached:
        cached['_cached'] = True
        return cached

    r = safe_get(
        f'https://api.example.com/v1/lookup?q={target}&key={api_key}',
        options=options,
    )
    if not r:
        return {'Erreur': 'Requête échouée'}
    if r.status_code == 401:
        return {'Erreur': 'Clé API invalide'}
    if r.status_code != 200:
        return {'Erreur': f'HTTP {r.status_code}'}

    data = r.json()
    out = {
        'Cible': target,
        'Résultat principal': data.get('result', 'N/A'),
    }
    set_cached('mon_service', target, out, ttl_hours=get_ttl_hours('mon_service'))
    return out
```

> **Cache** : utilisez toujours `get_cached` / `set_cached` — ne pas appeler `ApiCache.query` (conflit avec la colonne `query`).

### Étape 2 — Enregistrer dans `scan_modules.py`

```python
def scan_mon_service(target, options=None):
    key = _opt(options, '_mon_service_key', 'MON_API_KEY')
    from connectors.mon_service import search
    return search(target, key, options)


EXTRA_SCAN_FUNCTIONS['mon_service'] = scan_mon_service
```

Ajoutez aussi la clé dans `app.py` → `SCAN_FUNCTIONS` si le module doit apparaître dans la liste principale (souvent via `EXTRA_SCAN_FUNCTIONS.update`).

### Étape 3 — Bouton dans l’interface Expert

Dans `templates/index.html`, ajoutez un bouton module :

```html
<button class="mod" data-m="mon_service" title="Description">🔌 Mon Service</button>
```

Et un `placeholder` dans le JS `placeholders` si besoin.

### Étape 4 — Corrélation (optionnel)

Dans `services/correlation.py`, extrayez des entités depuis le résultat (emails, domaines, pseudos) pour alimenter le graphe `/graph`.

### Étape 5 — Documentation & tests

| Fichier | Action |
|---------|--------|
| `SECRETS.md` | Documenter `MON_API_KEY` |
| `templates/settings.html` | Champ clé utilisateur chiffrée |
| `services/cache.py` | Ajouter TTL dans `PROVIDER_TTL` si besoin |
| `tests/test_mon_service.py` | Test minimal avec mock HTTP |

Exemple de test :

```python
def test_mon_service_no_key():
    from connectors.mon_service import search
    out = search('test@example.com', '')
    assert 'Erreur' in out
```

## Structure du dépôt

| Dossier | Rôle |
|---------|------|
| `connectors/` | Sources externes (Hunter, Dehashed, …) |
| `services/` | Métier : cache, corrélation, IA, monitoring, PDF |
| `routes/` | Blueprints Flask (`views`, `api_v1`) |
| `scan_modules.py` | Enregistrement des modules de scan |
| `migrations/` | Alembic / Supabase |
| `templates/` | Express, Expert, monitoring, graphe |

## Migrations base de données

```bash
flask db revision -m "description"
flask db upgrade
```

## Tests

```bash
pytest tests/ -v
```

## Checklist pull request

- [ ] Connecteur avec gestion d'erreur et cache TTL
- [ ] Aucun secret en dur dans le code
- [ ] `SECRETS.md` et `CONTRIBUTING.md` à jour si nouveau connecteur
- [ ] `ROADMAP.md` statut mis à jour si fonctionnalité majeure
- [ ] Pas de fichiers binaires (PNG) dans le dépôt — Hugging Face les rejette

## Surveillance continue & Celery

- Surveillance UI : `/monitoring` (APScheduler toutes les 5 min)
- File optionnelle : `REDIS_URL` + `celery_app.py` / `tasks.py`

## Contact

Ouvrez une issue GitHub avec le label `enhancement` ou `bug` et décrivez le cas d’usage OSINT visé.
