"""Nettoyage des chaînes utilisateur avant construction d'URL HTTP."""
import re
from urllib.parse import urlparse

# Hostname RFC-like (simplifié)
_HOST_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)
_USERNAME_RE = re.compile(r'^[\w.\-]{1,64}$')


def sanitize_username(value: str, *, max_len: int = 64) -> str:
    """
    Pseudo / segment de chemin URL : sans espaces ni caractères dangereux.
  """
    v = (value or '').strip().lstrip('@')
    v = re.sub(r'\s+', '', v)
    v = re.sub(r'[^\w.\-]', '', v)
    return v[:max_len]


def is_valid_domain_host(host: str) -> bool:
    h = (host or '').strip().lower().replace('www.', '')
    if not h or ' ' in h or '/' in h or '@' in h:
        return False
    if h.startswith('http'):
        return False
    return bool(_HOST_RE.match(h))


def sanitize_domain_host(value: str) -> str | None:
    """Extrait un hostname utilisable ou None si invalide (téléphone, texte libre…)."""
    raw = (value or '').strip().lower()
    if not raw:
        return None
    for prefix in ('http://', 'https://', 'www.'):
        if raw.startswith(prefix):
            raw = raw[len(prefix):]
    host = raw.split('/')[0].split(':')[0].split('?')[0]
    if not is_valid_domain_host(host):
        return None
    return host


def _is_safe_http_host(host: str) -> bool:
    h = (host or '').strip().lower()
    if not h or ' ' in h or len(h) > 253:
        return False
    if not re.match(r'^[a-z0-9]([a-z0-9.\-]*[a-z0-9])?$', h):
        return False
    return '.' in h


def normalize_http_url(url: str) -> str | None:
    """
    Valide et normalise une URL avant GET cloudscraper/requests.
    Retourne None si la chaîne n'est pas une URL HTTP(S) sûre.
    """
    u = (url or '').strip()
    if not u:
        return None
    if any(c in u for c in ' \n\r\t'):
        return None
    if not u.startswith(('http://', 'https://')):
        host = sanitize_domain_host(u)
        if not host:
            return None
        return f'https://{host}'
    try:
        parsed = urlparse(u)
    except Exception:
        return None
    if parsed.scheme not in ('http', 'https'):
        return None
    host = (parsed.hostname or '').strip().lower()
    if not _is_safe_http_host(host):
        return None
    return u


def safe_path_segment(value: str, *, fallback: str = 'user') -> str:
    """Segment unique pour {u} dans les modèles d'URL de scan_pseudo."""
    seg = sanitize_username(value)
    return seg if seg and _USERNAME_RE.match(seg) else fallback
