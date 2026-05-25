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


def _parse_count(raw: str) -> int | str:
    try:
        return int(str(raw).replace(',', '').replace('\u202f', '').replace(' ', ''))
    except ValueError:
        return raw


def parse_instagram_og_meta(title: str = '', description: str = '', username: str = '') -> dict:
    """
    Parse og:description du type :
    « 882 Followers, 1,010 Following, 3 Posts - See … from Name (@user) »
    """
    out: dict = {}
    desc = (description or '').strip()
    title = (title or '').strip()
    if desc:
        for pat, key in [
            (r'([\d,.\s\u202f]+)\s+Followers', 'Followers'),
            (r'([\d,.\s\u202f]+)\s+Following', 'Following'),
            (r'([\d,.\s\u202f]+)\s+Posts', 'Publications'),
        ]:
            m = re.search(pat, desc, re.I)
            if m:
                out[key] = _parse_count(m.group(1))
        m_name = re.search(
            r'from\s+(.+?)\s+\(@([A-Za-z0-9._]+)\)',
            desc,
            re.I | re.DOTALL,
        )
        if m_name:
            out['Nom complet'] = m_name.group(1).strip()
            out['Pseudo confirmé'] = m_name.group(2).strip()
    if title and 'Nom complet' not in out:
        m_t = re.match(r'^(.+?)\s+\(@([A-Za-z0-9._]+)\)', title)
        if m_t:
            out['Nom complet'] = m_t.group(1).strip().rstrip('•').strip()
            out['Pseudo confirmé'] = m_t.group(2).strip()
    if username and not out.get('Pseudo confirmé'):
        out['Pseudo confirmé'] = username
    return out


def _extract_post_links_from_html(text: str, limit: int = 12) -> list[str]:
    """Liens /p/shortcode/ présents dans le JSON embarqué de la page."""
    seen: set[str] = set()
    links: list[str] = []
    for m in re.finditer(r'"shortcode":"([A-Za-z0-9_-]{5,})"', text or ''):
        code = m.group(1)
        if code in seen:
            continue
        seen.add(code)
        links.append(f'https://www.instagram.com/p/{code}/')
        if len(links) >= limit:
            break
    return links


def enrich_instagram_html_results(results: dict, text: str, username: str) -> dict:
    """Fusionne JSON embarqué + balises Open Graph en champs structurés."""
    if not results:
        results = {}
    title = results.pop('Titre', '') or ''
    desc = results.pop('Description', '') or ''
    og = parse_instagram_og_meta(title, desc, username)
    for key, val in og.items():
        if key not in results or results.get(key) in (None, '', 'N/A'):
            results[key] = val
    if title and 'Résumé Open Graph' not in results:
        results['Résumé Open Graph'] = title[:200]
    pic = None
    try:
        soup = BeautifulSoup(text or '', 'html.parser')
        el = soup.find('meta', property='og:image')
        if el and el.get('content'):
            pic = el['content']
    except Exception:
        pass
    if pic:
        results['Avatar URL'] = pic
    posts = _extract_post_links_from_html(text)
    if posts:
        results['Liens publications'] = [
            {'URL': u, 'Note': 'Ouvrir sur Instagram (aperçu non téléchargé sur HF)'}
            for u in posts
        ]
    elif results.get('Publications'):
        n = results.get('Publications')
        results['Liens publications'] = [{
            'URL': f'https://www.instagram.com/{username}/',
            'Note': f'{n} publication(s) — voir sur Instagram (photos non extraites en mode HF)',
        }]
    results['Profil'] = results.get('Profil') or f'https://www.instagram.com/{username}/'
    results['Mode'] = 'Scraping HTTP (Open Graph)'
    results['Photos / stories'] = (
        'Non disponibles sur Hugging Face — déployer sur VPS avec session-ig '
        '(instaloader) pour miniatures, stories et à la une.'
    )
    return results


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
    return enrich_instagram_html_results(results, text, username)


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
