"""WHOIS domaine — RDAP HTTP (whoisit + RDAP direct), sans socket port 43."""
import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from urllib.parse import quote

logger = logging.getLogger(__name__)

WHOIS_TIMEOUT_SEC = 8
_WHOISIT_READY = False


def _normalize_domain(domain: str) -> str:
    domain = (domain or '').strip().lower()
    for prefix in ('http://', 'https://', 'www.'):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    return domain.split('/')[0].split(':')[0]


def _ensure_whoisit():
    global _WHOISIT_READY
    if _WHOISIT_READY:
        return True
    try:
        import whoisit
        whoisit.bootstrap()
        _WHOISIT_READY = True
        return True
    except Exception as e:
        logger.debug('whoisit bootstrap: %s', e)
        return False


def _lookup_whoisit(domain: str) -> dict | None:
    """RDAP via lib whoisit (recommandé — HTTP uniquement)."""
    if not _ensure_whoisit():
        return None
    try:
        import whoisit
        data = whoisit.domain(domain)
        if not isinstance(data, dict):
            return None
        events = data.get('events') or {}
        if isinstance(events, dict):
            created = (events.get('registration') or events.get('registered') or 'N/A')[:10]
            expires = (events.get('expiration') or events.get('expiry') or 'N/A')[:10]
            updated = (events.get('last changed') or events.get('last_changed') or 'N/A')[:10]
        else:
            created = expires = updated = 'N/A'
        ent_block = data.get('entities') if isinstance(data.get('entities'), dict) else {}
        reg_ent = ent_block.get('registrar', {}) if isinstance(ent_block.get('registrar'), dict) else {}
        registrar = (
            data.get('registrar')
            or data.get('Registrar')
            or reg_ent.get('name')
            or 'N/A'
        )
        org = data.get('registrant') or data.get('organisation') or data.get('Organization') or 'N/A'
        if isinstance(org, dict):
            org = org.get('name') or org.get('fn') or 'N/A'
        country = data.get('country') or data.get('Country') or 'N/A'
        status = data.get('status') or data.get('Status') or 'N/A'
        if isinstance(status, list):
            status = ', '.join(str(s) for s in status[:3])
        out = {
            'Domaine': domain,
            'Registrar': str(registrar)[:200],
            'Création': str(created),
            'Expiration': str(expires),
            'Dernière MAJ': str(updated),
            'Pays': str(country)[:80],
            'Statut': str(status)[:200],
            'Organisation': str(org)[:200],
            '_source': 'whoisit-rdap',
        }
        if registrar == 'N/A' and org == 'N/A' and country == 'N/A':
            return None
        return out
    except Exception as e:
        logger.debug('whoisit domain %s: %s', domain, e)
        return None


def _parse_rdap_vcard(data: dict) -> dict:
    registrar = org = country = 'N/A'
    for ent in data.get('entities') or []:
        roles = ent.get('roles') or []
        vcard = ent.get('vcardArray')
        name = 'N/A'
        ent_country = None
        if isinstance(vcard, list) and len(vcard) > 1:
            for row in vcard[1]:
                if not isinstance(row, list) or len(row) < 4:
                    continue
                if row[0] == 'fn':
                    name = str(row[3])
                if row[0] == 'adr' and len(row) > 3 and isinstance(row[3], list):
                    parts = row[3]
                    if len(parts) >= 7 and parts[6]:
                        ent_country = str(parts[6])
        if 'registrar' in roles and registrar == 'N/A':
            registrar = name
        if 'registrant' in roles and org == 'N/A':
            org = name
            if ent_country:
                country = ent_country
    return {'registrar': registrar, 'org': org, 'country': country}


def _lookup_rdap_url(url: str, domain: str) -> dict | None:
    from services.http_client import safe_get
    try:
        r = safe_get(url, timeout=10)
        if not r or r.status_code != 200:
            return None
        data = r.json()
        events = data.get('events') or []
        created = updated = expires = 'N/A'
        for ev in events:
            action = (ev.get('eventAction') or '').lower()
            when = (ev.get('eventDate') or '')[:10]
            if action == 'registration':
                created = when
            elif action == 'expiration':
                expires = when
            elif action == 'last changed':
                updated = when
        vcard_info = _parse_rdap_vcard(data)
        status_list = data.get('status') or []
        status = ', '.join(status_list[:3]) if status_list else 'N/A'
        return {
            'Domaine': domain,
            'Registrar': vcard_info['registrar'],
            'Création': created,
            'Expiration': expires,
            'Dernière MAJ': updated,
            'Pays': vcard_info['country'],
            'Statut': status,
            'Organisation': vcard_info['org'],
            '_source': 'RDAP-HTTP',
        }
    except Exception as e:
        logger.debug('RDAP %s: %s', url[:60], e)
        return None


def _rdap_usable(result: dict | None) -> bool:
    if not result or result.get('Erreur'):
        return False
    return result.get('Registrar', 'N/A') != 'N/A' or result.get('Organisation', 'N/A') != 'N/A'


def _lookup_rdap(domain: str) -> dict | None:
    encoded = quote(domain, safe='')
    tld = domain.rsplit('.', 1)[-1] if '.' in domain else ''
    urls = [
        f'https://rdap.org/domain/{encoded}',
        f'https://rdap.verisign.com/com/v1/domain/{encoded}' if tld == 'com' else None,
        f'https://rdap.identitydigital.services/rdap/domain/{encoded}',
    ]
    for url in urls:
        if not url:
            continue
        result = _lookup_rdap_url(url, domain)
        if _rdap_usable(result):
            if result.get('Pays') in (None, 'N/A', ''):
                result['Pays'] = 'Non communiqué (RDAP)'
            return result
    return None


def _lookup_domainsdb(domain: str) -> dict | None:
    from services.http_client import safe_get
    try:
        r = safe_get(
            f'https://api.domainsdb.info/v1/domains/search?domain={quote(domain)}',
            timeout=10,
        )
        if not r or r.status_code != 200:
            return None
        rows = r.json()
        if not rows:
            return None
        row = rows[0] if isinstance(rows, list) else rows
        return {
            'Domaine': domain,
            'Registrar': row.get('registrar') or 'N/A',
            'Création': row.get('creation_date') or 'N/A',
            'Expiration': row.get('expiration_date') or 'N/A',
            'Pays': row.get('country') or 'N/A',
            'Statut': 'domainsdb.info',
            'Organisation': 'N/A',
            '_source': 'domainsdb',
        }
    except Exception as e:
        logger.debug('domainsdb %s: %s', domain, e)
        return None


def _lookup_pywhois(domain: str) -> dict:
    import whois as pywhois
    w = pywhois.whois(domain)
    cd = w.creation_date
    cd = cd[0] if isinstance(cd, list) else cd
    ed = w.expiration_date
    ed = ed[0] if isinstance(ed, list) else ed
    ud = w.updated_date
    ud = ud[0] if isinstance(ud, list) else ud
    return {
        'Domaine': domain,
        'Registrar': str(w.registrar or 'N/A'),
        'Création': str(cd or 'N/A'),
        'Expiration': str(ed or 'N/A'),
        'Dernière MAJ': str(ud or 'N/A'),
        'Pays': str(w.country or 'N/A'),
        'Statut': str(w.status or 'N/A'),
        'Name servers': w.name_servers if w.name_servers else [],
        'Emails WHOIS': w.emails if w.emails else [],
        'Organisation': str(w.org or 'N/A'),
        '_source': 'python-whois',
    }


def lookup(domain: str, options=None) -> dict:
    """Lookup WHOIS — whoisit/RDAP HTTP en priorité ; socket 43 en dernier recours."""
    domain = _normalize_domain(domain)
    if not domain or '.' not in domain:
        return {'Domaine': domain, 'Erreur': 'Domaine invalide', 'executed': True}

    from services.cache import get_cached, set_cached
    cached = get_cached('whois', domain)
    if cached and isinstance(cached, dict) and not cached.get('_timeout'):
        cached = dict(cached)
        cached['_cached'] = True
        cached['executed'] = True
        return cached

    for fetcher in (_lookup_whoisit, _lookup_rdap, _lookup_domainsdb):
        result = fetcher(domain)
        if _rdap_usable(result):
            result['executed'] = True
            set_cached('whois', domain, result, ttl_hours=72)
            return result

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            fut = pool.submit(_lookup_pywhois, domain)
            result = fut.result(timeout=WHOIS_TIMEOUT_SEC)
            result['executed'] = True
            set_cached('whois', domain, result, ttl_hours=72)
            return result
    except FuturesTimeout:
        return {
            'Domaine': domain,
            'Statut': 'Indisponible',
            'executed': True,
            'Message': (
                'WHOIS indisponible : RDAP HTTP (whoisit, rdap.org) et port 43 '
                f'ont échoué (timeout {WHOIS_TIMEOUT_SEC}s). '
                'Vérifiez le TLD ou réessayez — aucune donnée socket sur cet environnement.'
            ),
            '_timeout': True,
            '_source': 'none',
        }
    except Exception as e:
        err = str(e)
        if 'timed out' in err.lower():
            err = 'Port WHOIS 43 bloqué — seul RDAP HTTP est utilisé en production.'
        return {
            'Domaine': domain,
            'Statut': 'Indisponible',
            'executed': True,
            'Message': err[:400],
            '_timeout': True,
            '_source': 'none',
        }
