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

    r = safe_get(
        f'https://api.dehashed.com/v2/search?query={q}&size=20',
        headers=headers,
        options=options,
    )
    if not r:
        return {'Erreur': 'Requête Dehashed échouée'}
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
    leaks = []
    for e in entries[:20]:
        if isinstance(e, dict):
            leaks.append({
                'Email': e.get('email'),
                'Username': e.get('username'),
                'Base': e.get('database_name') or e.get('name'),
                'Date': e.get('obtained') or e.get('breach_date'),
            })
    out = {
        'Requête': q,
        'Fuites trouvées': len(leaks),
        'Entrées': leaks or ['Aucune entrée'],
    }
    set_cached('dehashed', q, out, ttl_hours=get_ttl_hours('dehashed'))
    return out
