"""Énumération de sous-domaines via Certificate Transparency (crt.sh).

Gratuit, sans clé API. Interroge les logs de transparence des certificats
pour cartographier l'infrastructure d'un domaine (sous-domaines exposés).
"""
import json

from services.http_client import safe_get
from services.url_sanitize import sanitize_domain_host

CRTSH_URL = 'https://crt.sh/'


def search_subdomains(domain, options=None) -> dict:
    host = sanitize_domain_host((domain or '').strip()) or ''
    if not host or '.' not in host:
        return {'Erreur': 'Domaine invalide pour crt.sh.', 'Cible reçue': str(domain)[:120]}

    # Requête simple (le wildcard %. de crt.sh est capricieux) ; le filtrage
    # strict par suffixe ci-dessous garantit qu'on ne garde que de vrais
    # sous-domaines du host demandé.
    url = f'{CRTSH_URL}?q={host}&output=json'
    try:
        r = safe_get(url, timeout=25, options=options)
    except Exception as e:  # noqa: BLE001
        return {'Erreur': f'crt.sh injoignable : {e}'}
    if not r or getattr(r, 'status_code', 0) != 200:
        return {'Erreur': f'crt.sh HTTP {getattr(r, "status_code", "?")}'}

    try:
        data = r.json()
    except Exception:
        # crt.sh renvoie parfois des objets JSON concaténés — réparation
        try:
            data = json.loads('[' + (r.text or '').strip().replace('}\n{', '},{') + ']')
        except Exception:
            return {'Erreur': 'Réponse crt.sh illisible.'}

    subs = set()
    for row in data or []:
        if not isinstance(row, dict):
            continue
        for name in str(row.get('name_value', '')).split('\n'):
            name = name.strip().lstrip('*.').lower()
            if name and name != host and name.endswith('.' + host) and ' ' not in name:
                subs.add(name)

    subs = sorted(subs)
    return {
        'Domaine': host,
        'Sous-domaines trouvés': len(subs),
        'Liste': subs[:300],
        'Source': 'Certificate Transparency (crt.sh)',
    }
