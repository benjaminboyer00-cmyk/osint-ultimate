"""Requêtes HTTP pour réseaux sociaux — cloudscraper puis repli requests."""
import json
import logging
import re

from bs4 import BeautifulSoup

from services.http_client import safe_get

logger = logging.getLogger(__name__)


def social_http_get(url: str, options=None, *, headers: dict | None = None, timeout: int = 15):
    """
    GET avec cloudscraper si autorisé (OPSEC), sinon session requests standard.
    """
    from services.url_sanitize import normalize_http_url

    opts = options or {}
    merged = dict(headers or {})
    safe_url = normalize_http_url(url)
    if not safe_url:
        logger.warning('social_http_get URL invalide: %r', (url or '')[:80])
        return None
    try:
        from connectors.scraper_fallback import fetch_url_protected
        r = fetch_url_protected(safe_url, opts)
        if r is not None and r.status_code < 500:
            return r
    except Exception as e:
        logger.debug('social_fetch cloudscraper %s: %s', url[:50], e)
    return safe_get(safe_url, timeout=timeout, options=opts, headers=merged)


def profile_exists_in_html(text: str, username: str) -> bool:
    """Heuristique : la page HTML correspond bien à ce pseudo (pas une 404 IG générique)."""
    if not text or not username:
        return False
    u = username.lower().strip()
    low = text.lower()
    if 'page not found' in low or 'sorry, this page' in low or "n'est pas disponible" in low:
        return False
    if f'instagram.com/{u}/' in low or f'instagram.com/{u}"' in low:
        return True
    if f'"username":"{u}"' in low:
        return True
    return False


def parse_instagram_profile_html(text: str, username: str) -> dict:
    """Extrait les champs visibles depuis la page HTML Instagram."""
    results: dict = {}
    if not text:
        return results
    for pattern, key in [
        (r'"edge_followed_by":\{"count":(\d+)\}', 'Followers'),
        (r'"edge_follow":\{"count":(\d+)\}', 'Following'),
        (r'"edge_owner_to_timeline_media":\{"count":(\d+)\}', 'Publications'),
    ]:
        m = re.search(pattern, text)
        if m:
            results[key] = int(m.group(1))
    for pattern, key in [
        (r'"full_name":"((?:\\.|[^"\\])*)"', 'Nom complet'),
        (r'"biography":"((?:\\.|[^"\\])*)"', 'Bio'),
    ]:
        m = re.search(pattern, text)
        if m:
            val = m.group(1).encode().decode('unicode_escape', errors='replace')
            results[key] = val.replace('\\n', '\n')
    if '"is_verified":true' in text:
        results['Vérifié'] = '✓ Oui'
    elif '"is_verified":false' in text:
        results['Vérifié'] = 'Non'
    if '"is_private":true' in text:
        results['Privé'] = 'Oui'
    elif '"is_private":false' in text:
        results['Privé'] = 'Non'
    try:
        soup = BeautifulSoup(text, 'html.parser')
        for prop, key in [('og:title', 'Titre'), ('og:description', 'Description')]:
            el = soup.find('meta', property=prop)
            if el and el.get('content'):
                results[key] = el['content']
    except Exception:
        pass
    results['Profil'] = f'https://www.instagram.com/{username}/'
    return results


def parse_instagram_api_json(data: dict) -> dict:
    user = (data or {}).get('data', {}).get('user') or {}
    if not user:
        return {}
    return {
        'Nom complet': user.get('full_name', ''),
        'Bio': user.get('biography', ''),
        'Followers': user.get('edge_followed_by', {}).get('count', 'N/A'),
        'Following': user.get('edge_follow', {}).get('count', 'N/A'),
        'Publications': user.get('edge_owner_to_timeline_media', {}).get('count', 'N/A'),
        'Vérifié': '✓ Oui' if user.get('is_verified') else 'Non',
        'Privé': 'Oui' if user.get('is_private') else 'Non',
        'Entreprise': 'Oui' if user.get('is_business_account') else 'Non',
        'Site web': user.get('external_url', ''),
        'Catégorie': user.get('category_name', ''),
        'Avatar URL': user.get('profile_pic_url_hd', ''),
        'Profil': f"https://www.instagram.com/{user.get('username', '')}/",
    }
