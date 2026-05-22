# Contribuer à OSINT Ultimate

Merci de votre intérêt pour le projet. Ce guide décrit comment ajouter un connecteur avec le **patron BaseConnector**, proposer une correction ou préparer une pull request.

## Prérequis

```bash
git clone <votre-fork>
cd osint-ultimate
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export FLASK_APP=app:app
export DATABASE_URL="sqlite:///osint.db"
flask db upgrade
python app.py
```

---

## Patron BaseConnector (recommandé)

Tous les nouveaux connecteurs devraient hériter de `connectors/base.py` pour bénéficier de :

- **Timeout** configurable par service  
- **Retry** HTTP (429, 5xx)  
- **Cache** via `db.session.query(ApiCache)` — **ne jamais** utiliser `ApiCache.query` (conflit avec la colonne SQL `query`)  
- Retour structuré : `(data, source)` avec `source` ∈ `cache | live | cache_expired | timeout | failed`

### Exemple minimal

```python
# connectors/mon_reseau.py
from connectors.base import BaseConnector


class MonReseauConnector(BaseConnector):
    name = 'mon_reseau'
    default_timeout = 10
    cache_ttl_hours = 48

    def search(self, target: str, api_key: str, options=None) -> dict:
        if not api_key:
            return {'Erreur': 'Clé API non configurée'}

        def fetch():
            r = self._request(
                f'https://api.example.com/user/{target}',
                timeout=12,
                options=options,
                headers={'Authorization': f'Bearer {api_key}'},
            )
            if not r:
                return {'_timeout': True, 'Message': 'Service lent ou indisponible'}
            d = r.json()
            return {'Pseudo': target, 'Profil': d.get('url', 'N/A')}

        data, source = self.get_cached_or_fetch(target, fetch, provider=self.name)
        if source == 'timeout':
            data['_status'] = 'timeout'
        if source == 'cache':
            data['_cached'] = True
        return data


# Instance singleton pour scan_modules
_connector = MonReseauConnector()


def search(target: str, api_key: str, options=None) -> dict:
    return _connector.search(target, api_key, options)
```

### Enregistrer le module (5 étapes)

| Étape | Fichier | Action |
|-------|---------|--------|
| 1 | `connectors/mon_reseau.py` | Classe + fonction `search()` |
| 2 | `scan_modules.py` | `scan_mon_reseau()` + `EXTRA_SCAN_FUNCTIONS['mon_reseau']` |
| 3 | `services/scanner.py` | Ajouter dans `SCAN_STRATEGIES` si pertinent (ex. `pseudo`) |
| 4 | `services/cache.py` | TTL dans `PROVIDER_TTL` (ex. `'mon_reseau': 48`) |
| 5 | `SECRETS.md`, `settings.html`, `index.html` | Clé API + bouton module |

```python
# scan_modules.py
def scan_mon_reseau(target, options=None):
    key = _opt(options, '_mon_reseau_key', 'MON_RESEAU_API_KEY')
    from connectors.mon_reseau import search
    return search(target, key, options)

EXTRA_SCAN_FUNCTIONS['mon_reseau'] = scan_mon_reseau
```

### Gestion des timeouts (non bloquant)

- Retourner `{'_timeout': True, 'Message': '…'}` plutôt qu'une exception.  
- Le scanner multi (`services/scanner.py`) classera le module dans `_meta.timeouts`.  
- L’UI Expert affiche un avertissement + bouton **Réessayer**.

### Corrélation graphe (optionnel)

Dans `services/correlation.py`, extraire emails / pseudos / domaines du résultat pour alimenter `/graph`.

---

## Scans multi-modules

- Stratégies : `SCAN_STRATEGIES` (Expert), `EXPRESS_STRATEGIES` (Express).  
- Lancement : `POST /scan` avec `{ "multi": true, "target": "…" }`.  
- Retry : `POST /scan/<id>/retry-timeouts`.

---

## Structure du dépôt

| Dossier | Rôle |
|---------|------|
| `connectors/` | Sources externes + `base.py` |
| `services/` | scanner, cache, corrélation, PDF, monitoring |
| `routes/` | Flask views + API v1 |
| `scan_modules.py` | Enregistrement des modules |
| `migrations/` | Alembic / Supabase |

---

## Migrations

```bash
flask db revision -m "description"
flask db upgrade
```

---

## Tests

```bash
pytest tests/ -v
```

---

## Checklist pull request

- [ ] Connecteur basé sur `BaseConnector` (ou migration documentée)
- [ ] Pas de `ApiCache.query` — uniquement `db.session.query(ApiCache)`
- [ ] Timeouts non bloquants (`_timeout`)
- [ ] Cache TTL + entrée `PROVIDER_TTL`
- [ ] Aucun secret en dur
- [ ] `SECRETS.md` mis à jour
- [ ] Pas de fichiers binaires (PNG) dans le dépôt

---

## Surveillance & Celery

- UI : `/monitoring` — graphe lié via `entity_id` ou `?target=`  
- Backend : APScheduler (5 min) ; Celery optionnel si `REDIS_URL`

---

## Contact

Issue GitHub avec label `enhancement` ou `bug` et le cas d’usage OSINT visé.
