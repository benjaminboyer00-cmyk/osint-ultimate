"""Vérification indicative des quotas API."""
import os
import requests


def check_groq(api_key: str) -> dict:
    if not api_key:
        return {'provider': 'groq', 'status': 'unconfigured'}
    return {
        'provider': 'groq',
        'status': 'ok',
        'note': 'Groq : consultez console.groq.com pour les limites du tier',
    }


def check_hunter(api_key: str) -> dict:
    if not api_key:
        return {'provider': 'hunter', 'status': 'unconfigured'}
    try:
        r = requests.get(
            f'https://api.hunter.io/v2/account?api_key={api_key}',
            timeout=10,
        )
        if r.status_code == 200:
            d = r.json().get('data', {})
            reqs = d.get('requests', {})
            used = reqs.get('used', 0)
            avail = reqs.get('available', 0)
            return {
                'provider': 'hunter',
                'status': 'warning' if avail and used / max(avail, 1) > 0.85 else 'ok',
                'used': used,
                'available': avail,
            }
        return {'provider': 'hunter', 'status': 'error', 'http': r.status_code}
    except Exception as e:
        return {'provider': 'hunter', 'status': 'error', 'message': str(e)}


def check_all_for_user(user, fernet) -> list:
    """Agrège les alertes quota pour un utilisateur."""
    keys = user.get_api_keys(fernet) if user else {}
    checks = [
        check_groq(os.environ.get('GROQ_API_KEY')),
        check_hunter(keys.get('hunter') or os.environ.get('HUNTER_API_KEY')),
    ]
    alerts = [c for c in checks if c.get('status') in ('warning', 'error')]
    return {'checks': checks, 'alerts': alerts, 'alert_count': len(alerts)}
