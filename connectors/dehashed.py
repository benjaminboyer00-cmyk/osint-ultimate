"""Dehashed — fuites de données."""
import base64
from services.cache import get_cached, set_cached, get_ttl_hours
from services.http_client import safe_get


def search(query: str, api_key: str, email: str = '', options=None) -> dict:
    if not api_key:
        return {'Erreur': 'Clé Dehashed non configurée (DEHASHED_API_KEY ou /settings)'}

    q = query.strip()
    cached = get_cached('dehashed', q)
    if cached:
        cached['_cached'] = True
        return cached

    headers = {'Accept': 'application/json'}
    if email:
        token = base64.b64encode(f'{email}:{api_key}'.encode()).decode()
        headers['Authorization'] = f'Basic {token}'
    else:
        headers['Authorization'] = f'Bearer {api_key}'

    opts = dict(options or {})
    opts['_retry'] = True
    r = safe_get(
        f'https://api.dehashed.com/v2/search?query={q}&size=20',
        headers=headers,
        options=opts,
        timeout=25,
    )
    if not r:
        return {
            'Erreur': 'Dehashed inaccessible (timeout réseau ou API). Vérifiez la clé et le quota.',
            '_timeout': True,
        }
    if r.status_code == 401:
        return {'Erreur': 'Identifiants Dehashed invalides (email + clé API)'}
    if r.status_code == 429:
        return {'Erreur': 'Dehashed HTTP 429 — quota atteint', '_quota': True}
    if r.status_code == 402:
        return {'Erreur': 'Dehashed — quota / abonnement requis', '_quota': True}
    if r.status_code != 200:
        err = f'Dehashed HTTP {r.status_code}'
        if r.status_code in (403, 503):
            return {'Erreur': err, '_quota': True}
        return {'Erreur': err}

    data = r.json()
    entries = data.get('entries') or data.get('results') or []

    def _first(e, *keys):
        """Dehashed renvoie parfois des listes (['x']) ou des scalaires."""
        for k in keys:
            v = e.get(k)
            if isinstance(v, list):
                v = next((x for x in v if x), None)
            if v:
                return str(v)
        return None

    leaks = []
    bases = set()
    for e in entries[:20]:
        if not isinstance(e, dict):
            continue
        pwd = _first(e, 'password')
        h = _first(e, 'hashed_password', 'hash')
        row = {
            'Base': _first(e, 'database_name', 'name') or 'Fuite (base inconnue)',
            'Date': _first(e, 'obtained', 'breach_date'),
            'Email': _first(e, 'email'),
            'Username': _first(e, 'username'),
            'Nom': _first(e, 'name', 'full_name'),
            'Téléphone': _first(e, 'phone'),
            'IP': _first(e, 'ip_address', 'ip'),
            'Adresse': _first(e, 'address'),
            # Le mot de passe en clair est la donnée la plus sensible : on l'expose
            # à l'utilisateur autorisé (c'est la fonction de l'outil) mais on signale
            # aussi la simple présence d'un hash.
            'Mot de passe': pwd,
            'Hash': ('présent' if h else None),
        }
        # ne garder que les champs renseignés (affichage propre)
        leaks.append({k: v for k, v in row.items() if v})
        if row['Base']:
            bases.add(row['Base'])

    out = {
        'Requête': q,
        'Fuites trouvées': len(leaks),
        'Bases concernées': sorted(bases) if bases else [],
        'Entrées': leaks or ['Aucune entrée'],
    }
    set_cached('dehashed', q, out, ttl_hours=get_ttl_hours('dehashed'))
    return out
