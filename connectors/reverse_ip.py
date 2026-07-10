"""Reverse IP — domaines hébergés sur la même IP (hébergement mutualisé).

Source gratuite sans clé : HackerTarget (limite ~quotidienne). Accepte une IP
ou un domaine (résolu en A au préalable).
"""
import re

from services.http_client import safe_get
from services.url_sanitize import sanitize_domain_host

HACKERTARGET_URL = 'https://api.hackertarget.com/reverseiplookup/'
_IPV4 = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')


def _resolve_to_ip(value: str) -> str | None:
    if _IPV4.match(value):
        return value
    host = sanitize_domain_host(value) or ''
    if not host:
        return None
    try:
        import dns.resolver
        r = dns.resolver.Resolver()
        r.lifetime = r.timeout = 3.0
        ans = r.resolve(host, 'A')
        return str(ans[0])
    except Exception:
        return None


def reverse_ip(target, options=None) -> dict:
    raw = (target or '').strip()
    ip = _resolve_to_ip(raw)
    if not ip:
        return {'Erreur': 'IP ou domaine résoluble attendu.', 'Cible reçue': raw[:120]}

    try:
        r = safe_get(f'{HACKERTARGET_URL}?q={ip}', timeout=20, options=options)
    except Exception as e:  # noqa: BLE001
        return {'Erreur': f'Service reverse-IP injoignable : {e}'}
    text = (getattr(r, 'text', '') or '').strip() if r else ''
    if not text:
        return {'Erreur': f'Réponse vide (HTTP {getattr(r, "status_code", "?")}).'}

    low = text.lower()
    if 'api count exceeded' in low or 'error' in low and 'check your' in low:
        return {'IP': ip, 'Message': 'Quota gratuit HackerTarget atteint — réessayez plus tard.',
                'Domaines trouvés': 0, 'Liste': []}
    if 'no records' in low or 'no dns' in low:
        return {'IP': ip, 'Domaines trouvés': 0, 'Liste': [],
                'Message': 'Aucun domaine associé trouvé.'}

    domains = sorted({
        d.strip().lower() for d in text.splitlines()
        if d.strip() and '.' in d and ' ' not in d.strip()
    })
    return {
        'IP': ip,
        'Domaines trouvés': len(domains),
        'Liste': domains[:300],
        'Source': 'HackerTarget (reverse IP)',
    }
