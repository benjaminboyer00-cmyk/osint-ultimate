"""Liens d'action Express → Expert avec module et cible pré-remplis."""
import re
from urllib.parse import quote

from services.target_detector import detect_target_type

# (regex sur le libellé, module expert)
_MODULE_HINTS = [
    (r'sherlock|pseudo|réseau|profil|300\+|comptes?', 'sherlock'),
    (r'hunter|emails?\s+pro|professionnel', 'hunter'),
    (r'dehashed|fuite|pwned|breach|compromis', 'dehashed'),
    (r'epieos', 'epieos'),
    (r'wayback|archive', 'wayback'),
    (r'whois', 'whois'),
    (r'téléphone|phone|numverify|sms', 'phone'),
    (r'\bip\b|shodan|géoloc', 'ip'),
    (r'instagram|tiktok|github|linkedin|facebook|twitter', 'pseudo'),
]


def _extract_target(text: str, default: str, card: dict, result: dict) -> str:
    m = re.search(r'[«\"]([^»\"]+)[»\"]', text)
    if m:
        return m.group(1).strip()
    m = re.search(r'[\w.\-]+@[\w.\-]+\.\w+', text)
    if m:
        return m.group(0)
    m = re.search(r'\b[\w.\-]{2,32}\b', text)
    if default and '@' in default and 'pseudo' in text.lower():
        return default.split('@')[0]
    return default or card.get('target', '')


def _guess_module(label: str, default_module: str) -> str:
    lower = label.lower()
    for pattern, mod in _MODULE_HINTS:
        if re.search(pattern, lower, re.I):
            return mod
    return default_module or detect_target_type(_extract_target(label, '', {}, {}))


def _normalize_target(module: str, target: str) -> str:
    t = (target or '').strip()
    if module == 'hunter' and '@' in t:
        t = t.split('@', 1)[1]
    if module in ('hunter', 'whois', 'site', 'wayback'):
        t = t.lower().replace('http://', '').replace('https://', '').split('/')[0].replace('www.', '')
    return t


def build_action_links(
    action_lines: list,
    module: str,
    target: str,
    card: dict | None = None,
    result: dict | None = None,
) -> list[dict]:
    """Transforme les suggestions texte en liens Expert exploitables."""
    card = card or {}
    result = result or {}
    links = []
    for raw in action_lines:
        label = re.sub(r'^[\d\.\)\-→\s]+', '', str(raw)).strip()
        if len(label) < 4:
            continue
        lower = label.lower()
        if re.search(r'graphe|corrél', lower):
            links.append({'label': label, 'url': '/graph', 'launch': False})
            continue
        if re.search(r'\bpdf\b|rapport', lower):
            continue

        mod = _guess_module(label, module)
        t = _normalize_target(mod, _extract_target(label, target, card, result))
        if not t:
            continue
        links.append({
            'label': label,
            'module': mod,
            'target': t,
            'url': f'/expert?module={mod}&target={quote(t)}',
            'launch': True,
        })
    return links[:6]
