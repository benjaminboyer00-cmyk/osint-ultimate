"""
Recherche OSINT par Google Dorks (DuckDuckGo HTML) — sans API payante.
"""
import logging
import random
import re
import time
from urllib.parse import quote_plus, urlparse

import requests
from bs4 import BeautifulSoup

from connectors.base import BaseConnector
from services.http_client import USER_AGENTS

logger = logging.getLogger(__name__)

DDG_HTML = 'https://html.duckduckgo.com/html/'
MAX_DORKS = 5
SEARCH_TIMEOUT = 9

# URLs de profils / documents
PROFILE_PATTERNS = [
    (r'https?://(?:www\.)?linkedin\.com/in/[\w\-%.]+', 'linkedin', 'platform'),
    (r'https?://(?:www\.)?twitter\.com/[\w]+', 'twitter', 'platform'),
    (r'https?://(?:www\.)?x\.com/[\w]+', 'twitter', 'platform'),
    (r'https?://(?:www\.)?github\.com/[\w\-]+', 'github', 'platform'),
    (r'https?://(?:www\.)?instagram\.com/[\w.]+', 'instagram', 'platform'),
    (r'https?://(?:www\.)?facebook\.com/[\w.]+', 'facebook', 'platform'),
]
DOC_EXT = ('.pdf', '.doc', '.docx', '.ppt', '.pptx', '.xls', '.xlsx')
EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')


def build_linkedin_dork(name: str) -> dict:
    q = name.strip().replace('"', '')
    return {'engine': 'duckduckgo', 'category': 'linkedin', 'query': f'site:linkedin.com "{q}"'}


def build_twitter_dork(pseudo: str) -> dict:
    p = pseudo.strip().lstrip('@').replace('"', '')
    return {'engine': 'duckduckgo', 'category': 'twitter', 'query': f'site:twitter.com OR site:x.com "{p}"'}


def build_github_dork(pseudo: str) -> dict:
    p = pseudo.strip().lstrip('@')
    return {'engine': 'duckduckgo', 'category': 'github', 'query': f'site:github.com "{p}"'}


def build_document_dork(domain: str) -> dict:
    d = domain.strip().lower().replace('www.', '').split('/')[0]
    return {'engine': 'duckduckgo', 'category': 'documents', 'query': f'site:{d} filetype:pdf OR filetype:doc'}


def build_email_mention_dork(email: str) -> dict:
    return {'engine': 'duckduckgo', 'category': 'mentions', 'query': f'"{email.strip()}"'}


def build_domain_email_dork(domain: str) -> dict:
    d = domain.strip().lower().replace('www.', '').split('/')[0]
    return {'engine': 'duckduckgo', 'category': 'emails', 'query': f'"@{d}" email OR contact'}


def build_pseudo_dork(pseudo: str) -> dict:
    p = pseudo.strip().lstrip('@').replace('"', '')
    return {'engine': 'duckduckgo', 'category': 'pseudo', 'query': f'"{p}" profile OR account'}


def build_name_dork(name: str) -> dict:
    return {'engine': 'duckduckgo', 'category': 'general', 'query': f'"{name.strip()}"'}


class DorkingConnector(BaseConnector):
    """Génère et exécute des dorks selon le type de cible."""

    name = 'dorking'
    cache_ttl_hours = 12

    def __init__(self, target_type: str, target_value: str, **kwargs):
        super().__init__(name='dorking', cache_ttl_hours=12, **kwargs)
        self.target_type = (target_type or 'pseudo').lower()
        self.target_value = (target_value or '').strip()

    def generate_dorks(self) -> list[dict]:
        t = self.target_value
        tt = self.target_type
        dorks = []

        if tt == 'email' or '@' in t:
            email = t if '@' in t else t
            domain = email.split('@')[1] if '@' in email else t
            dorks.append(build_email_mention_dork(email if '@' in email else f'x@{domain}'))
            if domain and '.' in domain:
                dorks.append(build_domain_email_dork(domain))
            local = email.split('@')[0] if '@' in email else email
            if len(local) >= 2:
                dorks.append(build_linkedin_dork(local))
                dorks.append(build_github_dork(local))
        elif tt in ('pseudo', 'username'):
            dorks.extend([
                build_pseudo_dork(t),
                build_twitter_dork(t),
                build_github_dork(t),
                build_linkedin_dork(t),
            ])
        elif tt in ('domain', 'site'):
            domain = t.replace('http://', '').replace('https://', '').split('/')[0]
            dorks.extend([
                build_document_dork(domain),
                build_domain_email_dork(domain),
                {'engine': 'duckduckgo', 'category': 'site', 'query': f'site:{domain}'},
            ])
        elif tt == 'phone':
            digits = re.sub(r'\D', '', t)
            dorks.append({'engine': 'duckduckgo', 'category': 'phone', 'query': f'"{digits}" OR "{t}"'})
        else:
            dorks.append(build_pseudo_dork(t))
            if ' ' in t:
                dorks.append(build_name_dork(t))

        seen = set()
        unique = []
        for d in dorks:
            q = d.get('query', '')
            if q and q not in seen:
                seen.add(q)
                unique.append(d)
        return unique[:MAX_DORKS]

    def _ddg_headers(self, options=None) -> dict:
        opts = options or {}
        if opts.get('_stealth_mode'):
            time.sleep(random.uniform(0.3, 1.2))
        return {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html',
            'Accept-Language': 'fr-FR,fr;q=0.9,en;q=0.8',
        }

    def _proxies(self, options=None):
        opts = options or {}
        raw = opts.get('_proxy_list') or ''
        if not raw:
            return None
        proxies = [p.strip() for p in str(raw).split(',') if p.strip()]
        if not proxies:
            return None
        p = random.choice(proxies)
        return {'http': p, 'https': p}

    def search_dork(self, query: str, engine: str = 'duckduckgo', options=None) -> list[dict]:
        """Exécute un dork ; retourne [{url, title, snippet}, ...]."""
        if engine != 'duckduckgo':
            return []
        opts = options or {}
        logger.info('Dork search: %s', query[:100])
        try:
            r = requests.post(
                DDG_HTML,
                headers=self._ddg_headers(opts),
                data={'q': query},
                timeout=SEARCH_TIMEOUT,
                proxies=self._proxies(opts),
                verify=False,
            )
            r.raise_for_status()
        except Exception as e:
            logger.warning('Dork échec: %s — %s', query[:60], e)
            return []

        soup = BeautifulSoup(r.text, 'html.parser')
        hits = []
        for result in soup.select('.result, .web-result')[:15]:
            link = result.select_one('a.result__a, a.result__url')
            snippet_el = result.select_one('.result__snippet, .result__body')
            if not link:
                continue
            url = link.get('href') or ''
            if url.startswith('//'):
                url = 'https:' + url
            title = link.get_text(' ', strip=True)[:200]
            snippet = snippet_el.get_text(' ', strip=True)[:300] if snippet_el else ''
            if url.startswith('http'):
                hits.append({'url': url, 'title': title, 'snippet': snippet, 'query': query})
        logger.info('Dork %r → %s résultats', query[:50], len(hits))
        return hits

    def extract_profiles(self, html: str, source_query: str = '') -> list[dict]:
        """Extrait entités standardisées depuis HTML ou texte agrégé."""
        entities = []
        seen = set()

        for pattern, platform, etype in PROFILE_PATTERNS:
            for url in re.findall(pattern, html, re.I):
                key = (etype, url.lower())
                if key in seen:
                    continue
                seen.add(key)
                entities.append({
                    'type': etype,
                    'value': url,
                    'source': 'dorking',
                    'confidence': 0.55,
                    'platform': platform,
                    'url': url,
                    'snippet': '',
                })

        for em in EMAIL_RE.findall(html):
            em_l = em.lower()
            if em_l in seen or len(em) > 80:
                continue
            seen.add(em_l)
            entities.append({
                'type': 'email',
                'value': em_l,
                'source': 'dorking',
                'confidence': 0.5,
                'url': '',
                'snippet': source_query[:120],
            })

        for m in re.finditer(r'https?://[^\s<>"\']+', html, re.I):
            url = m.group(0).rstrip('.,;)')
            low = url.lower()
            if any(low.endswith(ext) for ext in DOC_EXT):
                if ('document', url) not in seen:
                    seen.add(('document', url))
                    entities.append({
                        'type': 'document',
                        'value': url,
                        'source': 'dorking',
                        'confidence': 0.45,
                        'url': url,
                        'snippet': '',
                    })
        return entities

    def _hits_to_entities(self, hits: list[dict]) -> list[dict]:
        entities = []
        seen = set()
        blob = '\n'.join(
            f"{h.get('url','')} {h.get('title','')} {h.get('snippet','')}" for h in hits
        )
        for ent in self.extract_profiles(blob):
            key = (ent['type'], ent.get('value', '').lower())
            if key not in seen:
                seen.add(key)
                entities.append(ent)

        # URLs brutes : uniquement si déjà validées via extract_profiles
        return entities[:40]

    def run(self, options=None) -> dict:
        """Orchestre dorks + extraction ; retourne payload scan standard."""
        opts = options or {}
        cache_key = f'{self.target_type}:{self.target_value.lower()}'

        def fetch():
            dorks = self.generate_dorks()
            if not dorks:
                return {
                    'Cible': self.target_value,
                    'Type': self.target_type,
                    'Message': 'Aucun dork généré pour cette cible',
                    'Entités': [],
                }

            all_hits = []
            all_entities = []
            dork_log = []

            for d in dorks:
                if opts.get('_scrape_fallback') is False:
                    continue
                hits = self.search_dork(d['query'], d.get('engine', 'duckduckgo'), opts)
                dork_log.append({
                    'catégorie': d.get('category'),
                    'requête': d['query'],
                    'résultats': len(hits),
                })
                all_hits.extend(hits)
                time.sleep(random.uniform(0.4, 1.0) if opts.get('_stealth_mode') else 0.2)

            all_entities = self._hits_to_entities(all_hits)
            from services.dorking_filter import filter_dorking_entities
            all_entities = filter_dorking_entities(
                all_entities, self.target_value, self.target_type,
            )
            profiles = [e for e in all_entities if e['type'] in ('platform', 'url')]
            emails = [e['value'] for e in all_entities if e['type'] == 'email']
            docs = [e['value'] for e in all_entities if e['type'] == 'document']

            return {
                'Cible': self.target_value,
                'Type': self.target_type,
                'Dorks exécutés': len(dorks),
                'Détail dorks': dork_log,
                'URLs trouvées': len(all_hits),
                'Profils et URLs': [
                    {'URL': e.get('value'), 'Plateforme': e.get('platform', '—'), 'Confiance': e.get('confidence')}
                    for e in profiles[:20]
                ],
                'Emails trouvés': emails[:15],
                'Documents': docs[:10],
                'Entités': all_entities,
                'Message': (
                    f'{len(all_entities)} indicateur(s) via recherche profonde (DuckDuckGo).'
                    if all_entities
                    else 'Aucun résultat public — réessayez en mode furtif ou avec proxy.'
                ),
            }

        data, source = self.get_cached_or_fetch(cache_key, fetch, provider='dorking')
        if isinstance(data, dict):
            data['_source'] = source
        return data


def search(target: str, options=None) -> dict:
    """Point d'entrée module scan."""
    from services.target_detector import target_category, detect_target_type

    cat = target_category(target)
    if cat == 'pseudo' and detect_target_type(target) == 'email':
        cat = 'email'
    conn = DorkingConnector(cat, target)
    return conn.run(options)
