"""Epieos — email / pseudo (API si clé disponible)."""
from services.http_client import safe_get


def search(target: str, api_key: str = '', options=None) -> dict:
    target = target.strip()
    if not api_key:
        return {
            'Note': 'Configurez EPIEOS_API_KEY dans les secrets ou /settings',
            'Cible': target,
            'Lien manuel': f'https://epieos.com/?q={target}',
            'Statut': 'Recherche manuelle recommandée (pas de clé API)',
        }

    r = safe_get(
        f'https://api.epieos.com/v1/search?q={target}',
        headers={'Authorization': f'Bearer {api_key}', 'Accept': 'application/json'},
        options=options,
    )
    if not r:
        return {'Erreur': 'Epieos inaccessible', 'Lien': f'https://epieos.com/?q={target}'}
    if r.status_code == 401:
        return {'Erreur': 'Clé Epieos invalide'}
    if r.status_code != 200:
        return {
            'Erreur': f'Epieos HTTP {r.status_code}',
            'Lien manuel': f'https://epieos.com/?q={target}',
        }
    try:
        return {'Epieos': r.json(), 'Cible': target}
    except Exception:
        return {'Erreur': 'Réponse Epieos illisible'}
