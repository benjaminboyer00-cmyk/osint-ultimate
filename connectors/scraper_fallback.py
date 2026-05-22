"""
Fallback scraping HTTP (DuckDuckGo HTML + cloudscraper) — sans Playwright.
Utilisé quand Hunter / Dehashed renvoient 429 ou quota, ou pages Cloudflare.
"""
import hashlib
import json
import logging
import random
import re
import time

import requests
from bs4 import BeautifulSoup
from cachetools import TTLCache

from services.http_client import USER_AGENTS, SSL_VERIFY
from services.scrape_policy import cloudflare_scrape_allowed

logger = logging.getLogger(__name__)

DDG_HTML_URL = 'https://html.duckduckgo.com/html/'
SCRAPE_TIMEOUT = 10
# Max 50 sessions cloudscraper, TTL 2 h — évite fuite mémoire sur long uptime
_scraper_cache = TTLCache(maxsize=50, ttl=7200)


def _scraper_cache_key(options=None) -> str:
    """Hash stable des options pertinentes (sans clés API)."""
    opts = options or {}
    subset = {
        '_proxy_list': opts.get('_proxy_list', 'default'),
        '_stealth_mode': bool(opts.get('_stealth_mode')),
    }
    raw = json.dumps(subset, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


def _get_cloudscraper(options=None):
    """Session cloudscraper réutilisable (contournement anti-bot basique)."""
    key = _scraper_cache_key(options)
    if key in _scraper_cache:
        return _scraper_cache[key]
    import cloudscraper
    scraper = cloudscraper.create_scraper(
        browser={'browser': 'chrome', 'platform': 'windows', 'mobile': False},
        delay=10,
    )
    _scraper_cache[key] = scraper
    return scraper


def fetch_url_protected(url: str, options=None):
    """
    GET via cloudscraper — pour cibles directes protégées Cloudflare.
    Retourne l'objet Response requests-like ou None.
    """
    if not cloudflare_scrape_allowed(options):
        return None
    url = (url or '').strip()
    if not url.startswith('http'):
        url = f'https://{url}'
    try:
        scraper = _get_cloudscraper(options)
        return scraper.get(
            url,
            timeout=SCRAPE_TIMEOUT + 5,
            proxies=_proxy_dict(options),
            verify=SSL_VERIFY,
        )
    except Exception as e:
        logger.warning('cloudscraper %s: %s', url[:60], e)
        return None


def _headers(options=None) -> dict:
    opts = options or {}
    if opts.get('_stealth_mode'):
        time.sleep(random.uniform(0.4, 1.5))
    return {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml',
        'Accept-Language': 'fr-FR,fr;q=0.9,en;q=0.8',
    }


def _proxy_dict(options=None) -> dict | None:
    opts = options or {}
    raw = opts.get('_proxy_list') or ''
    if not raw:
        return None
    proxies = [p.strip() for p in str(raw).split(',') if p.strip()]
    if not proxies:
        return None
    p = random.choice(proxies)
    return {'http': p, 'https': p}


def _ddg_search(query: str, options=None) -> str:
    """POST DuckDuckGo HTML — retourne le texte brut ou chaîne vide."""
    logger.info('DDG scrape: requête=%r stealth=%s', query[:80], bool((options or {}).get('_stealth_mode')))
    try:
        r = requests.post(
            DDG_HTML_URL,
            headers=_headers(options),
            data={'q': query},
            timeout=SCRAPE_TIMEOUT,
            proxies=_proxy_dict(options),
            verify=SSL_VERIFY,
        )
        r.raise_for_status()
        logger.info('DDG scrape: OK (%s octets)', len(r.text))
        return r.text
    except Exception as e:
        logger.warning('DDG scrape échec: %s — query=%r', e, query[:60])
        return ''


def fallback_scrape_emails(domain: str, options=None) -> list[dict]:
    """
    Dork emails pour un domaine via DuckDuckGo HTML.
    Retourne liste au format Hunter (Liste).
    """
    domain = domain.strip().lower().split('/')[0].replace('www.', '')
    if not domain or '.' not in domain:
        return []

    query = f'"{domain}" email OR contact OR "@{domain}"'
    html = _ddg_search(query, options)
    source = 'duckduckgo'
    if not html:
        logger.info('DDG vide pour %s — tentative cloudscraper', domain)
        resp = fetch_url_protected(f'https://{domain}', options)
        html = resp.text if resp and resp.text else ''
        source = 'cloudscraper' if html else 'none'
    if not html:
        logger.warning('Aucun HTML récupéré pour emails domaine %s', domain)
        return []

    soup = BeautifulSoup(html, 'html.parser')
    text = soup.get_text(' ', strip=True)
    pattern = r'[a-zA-Z0-9._%+-]+@' + re.escape(domain) + r'\b'
    found = sorted(set(re.findall(pattern, text, re.I)))
    logger.info('Emails trouvés pour %s: %s (source=%s)', domain, len(found), source)

    return [
        {
            'Email': em,
            'Type': 'scraped',
            'Confiance': None,
            'Prénom': None,
            'Nom': None,
            'Poste': 'Source publique (scraping)',
        }
        for em in found[:15]
    ]


def fallback_scrape_dehashed_hints(query: str, options=None) -> list[dict]:
    """
    Indices publics (snippets) — pas de données de fuite inventées.
    """
    q = query.strip()
    if not q:
        return []

    dork = f'"{q}" leak OR breach OR paste OR "data breach"'
    html = _ddg_search(dork, options)
    if not html:
        return []

    soup = BeautifulSoup(html, 'html.parser')
    snippets = []
    for block in soup.select('.result__snippet, .result__body')[:12]:
        t = block.get_text(' ', strip=True)
        if t and len(t) > 20:
            snippets.append(t[:280])

    if not snippets:
        text = soup.get_text(' ', strip=True)
        for chunk in re.split(r'\s{2,}', text):
            if q.lower() in chunk.lower() and 30 < len(chunk) < 300:
                snippets.append(chunk[:280])
            if len(snippets) >= 8:
                break

    return [
        {
            'Email': None,
            'Username': q,
            'Base': 'Indice web public',
            'Date': None,
            'Snippet': sn,
        }
        for sn in snippets[:8]
    ]
