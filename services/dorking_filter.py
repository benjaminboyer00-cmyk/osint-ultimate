"""Filtrage des entités Dorking — réduit les faux positifs dans le graphe."""
import re
from urllib.parse import urlparse

# Mots / motifs bruit DuckDuckGo
NOISE_RE = re.compile(
    r'^(login|signup|register|search|home|about|contact|privacy|terms|wiki|help|'
    r'javascript|undefined|null|true|false)$',
    re.I,
)
HANDLE_RE = re.compile(r'^[\w][\w.\-]{1,31}$')


def _target_tokens(target: str) -> set[str]:
    t = (target or '').lower()
    parts = re.findall(r'[\w]{3,}', t.replace('@', ' ').replace('.', ' '))
    return {p for p in parts if len(p) >= 3 and not p.isdigit()}


def extract_profile_handle(url: str, platform: str = '') -> str:
    """Extrait pseudo / slug depuis une URL de profil."""
    try:
        path = urlparse(url.lower()).path.strip('/')
    except Exception:
        return ''
    if not path:
        return ''
    if 'linkedin.com' in url.lower() and '/in/' in url.lower():
        m = re.search(r'/in/([\w\-%.]+)', url, re.I)
        return (m.group(1) if m else '').lower()
    if 'github.com' in url.lower():
        parts = path.split('/')
        return (parts[0] if parts else '').lower()
    if 'twitter.com' in url.lower() or 'x.com' in url.lower():
        parts = path.split('/')
        return (parts[0] if parts else '').lower()
    return path.split('/')[-1].lower()[:40]


def is_relevant_entity(
    value: str,
    etype: str,
    target: str,
    target_type: str,
    *,
    min_confidence: float = 0.45,
    confidence: float = 0.5,
) -> bool:
    """
    Retourne False si l'entité ne doit pas être ajoutée au graphe.
    """
    if confidence < min_confidence:
        return False

    val = (value or '').strip()
    if not val or len(val) > 500:
        return False

    target_l = (target or '').lower().strip()
    val_l = val.lower()
    tt = (target_type or '').lower()

    if NOISE_RE.match(val_l.split('/')[-1]):
        return False

    # Emails : doit être cohérent avec la cible
    if etype == 'email':
        if '@' not in val_l:
            return False
        if '@' in target_l:
            tdom = target_l.split('@')[1]
            return tdom in val_l or target_l.split('@')[0] in val_l
        return True

    # Domaines
    if etype == 'domain':
        dom = target_l.replace('www.', '').split('/')[0]
        if '@' in target_l:
            dom = target_l.split('@')[1]
        return dom and (dom in val_l or val_l.endswith('.' + dom) or val_l == dom)

    # Profils / plateformes (URL ou pseudo)
    if etype in ('platform', 'username', 'url'):
        handle = extract_profile_handle(val_l) if val_l.startswith('http') else val_l.lstrip('@')
        if not handle or len(handle) < 2:
            return False
        if not HANDLE_RE.match(handle.replace('%', '')):
            return False

        # Cible email : n'accepter que si le handle correspond au local-part
        if '@' in target_l or tt == 'email':
            local = target_l.split('@')[0] if '@' in target_l else ''
            if len(local) < 2:
                return False
            if local not in handle and handle not in local:
                return False
            return True

        if tt in ('pseudo', 'username'):
            p = target_l.lstrip('@').split('/')[0]
            return p in handle or handle in p or p in val_l

        if tt in ('domain', 'site'):
            dom = target_l.replace('www.', '').split('/')[0]
            return dom in val_l

        # Nom / texte libre : recoupement de tokens
        tokens = _target_tokens(target_l)
        if tokens:
            h_tokens = set(re.findall(r'[\w]{3,}', handle.replace('.', ' ')))
            return bool(tokens & h_tokens)
        return len(handle) >= 4

    if etype == 'document':
        if tt in ('domain', 'site'):
            dom = target_l.replace('www.', '').split('/')[0]
            return dom in val_l
        return True

    return len(val_l) >= 5


def filter_dorking_entities(entities: list, target: str, target_type: str) -> list:
    """Filtre la liste Entités avant corrélation / affichage."""
    out = []
    seen = set()
    for item in entities or []:
        if not isinstance(item, dict):
            continue
        val = (item.get('value') or item.get('url') or '').strip()
        etype = item.get('type', 'unknown')
        conf = float(item.get('confidence') or 0.5)
        if not is_relevant_entity(val, etype, target, target_type, confidence=conf):
            continue
        key = (etype, val.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out
