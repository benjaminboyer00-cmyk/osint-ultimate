"""WHOIS domaine — RDAP HTTP (prioritaire), repli python-whois court."""
import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from urllib.parse import quote

logger = logging.getLogger(__name__)

WHOIS_TIMEOUT_SEC = 10


def _normalize_domain(domain: str) -> str:
    domain = (domain or '').strip().lower()
    for prefix in ('http://', 'https://', 'www.'):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    return domain.split('/')[0].split(':')[0]


def _parse_rdap_vcard(data: dict) -> dict:
    """Extrait registrar / pays depuis vcardArray RDAP."""
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
                    # adr: [, , , , , , country]
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
            '_source': 'RDAP',
        }
    except Exception as e:
        logger.debug('RDAP %s: %s', url[:60], e)
        return None


def _lookup_rdap(domain: str) -> dict | None:
    """RDAP via plusieurs points d'entrée (compatible HF, sans port 43)."""
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
        if result and not result.get('Erreur'):
            if result.get('Pays') in (None, 'N/A', ''):
                result['Pays'] = 'Non communiqué (RDAP)'
            return result
    return None


def _lookup_domainsdb(domain: str) -> dict | None:
    """Repli HTTP léger (registrar / pays)."""
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
    domain = _normalize_domain(domain)
    if not domain or '.' not in domain:
        return {'Domaine': domain, 'Erreur': 'Domaine invalide'}

    from services.cache import get_cached, set_cached
    cached = get_cached('whois', domain)
    if cached and isinstance(cached, dict) and not cached.get('_timeout'):
        cached['_cached'] = True
        return cached

    for fetcher in (_lookup_rdap, _lookup_domainsdb):
        result = fetcher(domain)
        if result and not result.get('Erreur'):
            set_cached('whois', domain, result, ttl_hours=72)
            return result

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            fut = pool.submit(_lookup_pywhois, domain)
            result = fut.result(timeout=WHOIS_TIMEOUT_SEC)
            set_cached('whois', domain, result, ttl_hours=72)
            return result
    except FuturesTimeout:
        out = {
            'Domaine': domain,
            'Statut': 'Indisponible',
            'Message': (
                f'WHOIS indisponible (timeout {WHOIS_TIMEOUT_SEC}s). '
                'Les registres RDAP et le port 43 n\'ont pas répondu — réessayez plus tard.'
            ),
            '_timeout': True,
            '_source': 'none',
        }
        return out
    except Exception as e:
        err = str(e)
        if 'timed out' in err.lower():
            err = 'Connexion WHOIS classique bloquée — RDAP n\'a pas fourni de données.'
        return {
            'Domaine': domain,
            'Statut': 'Indisponible',
            'Message': err[:400],
            '_timeout': True,
            '_source': 'none',
        }
