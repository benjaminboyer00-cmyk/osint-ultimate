"""Détection automatique du type de cible (mode Express)."""
import re

EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
IP_RE = re.compile(r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$')
PHONE_RE = re.compile(r'^[\+]?[\d\s\.\-\(\)]{8,20}$')
DOMAIN_RE = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')


def detect_target_type(target: str) -> str:
    """Retourne le module de scan le plus adapté."""
    t = (target or '').strip()
    if not t:
        return 'pseudo'
    if EMAIL_RE.match(t):
        return 'email'
    if IP_RE.match(t):
        return 'ip'
    if t.startswith('http://') or t.startswith('https://'):
        return 'site'
    if DOMAIN_RE.match(t) and '@' not in t:
        return 'site'
    digits = re.sub(r'\D', '', t)
    if len(digits) >= 8 and PHONE_RE.match(t):
        return 'phone'
    if re.match(r'^[@]?[\w\.\-]{2,32}$', t):
        return 'sherlock'
    return 'pseudo'


def express_label(module: str) -> str:
    labels = {
        'email': 'Adresse email',
        'phone': 'Numéro de téléphone',
        'ip': 'Adresse IP',
        'site': 'Site web',
        'sherlock': 'Pseudo (Sherlock)',
        'pseudo': 'Pseudo',
    }
    return labels.get(module, module)
