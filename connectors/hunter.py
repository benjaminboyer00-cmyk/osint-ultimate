"""Hunter.io — emails professionnels par domaine."""
from services.cache import get_cached, set_cached, get_ttl_hours
from services.http_client import safe_get


def search_domain(domain: str, api_key: str, options=None) -> dict:
    domain = domain.strip().lower().replace('http://', '').replace('https://', '').split('/')[0]
    domain = domain.replace('www.', '')
    if not api_key:
        return {'Erreur': 'Clé Hunter.io non configurée (HUNTER_API_KEY ou /settings)'}

    cached = get_cached('hunter', domain)
    if cached:
        cached['_cached'] = True
        return cached

    r = safe_get(
        f'https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}&limit=10',
        options=options,
    )
    if not r:
        return {'Erreur': 'Requête Hunter.io échouée'}
    if r.status_code == 401:
        return {'Erreur': 'Clé Hunter.io invalide'}
    if r.status_code == 429:
        return {'Erreur': 'Hunter HTTP 429 — quota / rate limit atteint', '_quota': True}
    if r.status_code == 402:
        return {'Erreur': 'Hunter — plan / quota insuffisant', '_quota': True}
    if r.status_code != 200:
        err = f'Hunter HTTP {r.status_code}'
        if r.status_code in (403, 503):
            return {'Erreur': err, '_quota': True}
        return {'Erreur': err}

    d = r.json().get('data', {})
    emails = []
    for e in (d.get('emails') or [])[:15]:
        emails.append({
            'Email': e.get('value'),
            'Type': e.get('type'),
            'Confiance': e.get('confidence'),
            'Prénom': e.get('first_name'),
            'Nom': e.get('last_name'),
            'Poste': e.get('position'),
        })
    out = {
        'Domaine': domain,
        'Organisation': d.get('organization'),
        'Emails trouvés': len(emails),
        'Liste': emails,
        'Email pattern': d.get('pattern'),
    }
    set_cached('hunter', domain, out, ttl_hours=get_ttl_hours('hunter'))
    return out
