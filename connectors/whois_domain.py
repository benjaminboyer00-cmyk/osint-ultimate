"""WHOIS domaine — RDAP HTTP puis repli python-whois (timeouts courts)."""
import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout

logger = logging.getLogger(__name__)

WHOIS_TIMEOUT_SEC = 12


def _normalize_domain(domain: str) -> str:
    domain = (domain or '').strip().lower()
    for prefix in ('http://', 'https://', 'www.'):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    return domain.split('/')[0].split(':')[0]


def _lookup_rdap(domain: str) -> dict | None:
    """RDAP via HTTP (rapide, compatible HF)."""
    from services.http_client import safe_get
    try:
        r = safe_get(f'https://rdap.org/domain/{domain}', timeout=10)
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
        entities = data.get('entities') or []
        registrar = org = 'N/A'
        for ent in entities:
            roles = ent.get('roles') or []
            vcard = ent.get('vcardArray')
            name = 'N/A'
            if isinstance(vcard, list) and len(vcard) > 1:
                for row in vcard[1]:
                    if isinstance(row, list) and len(row) >= 4 and row[0] == 'fn':
                        name = str(row[3])
            if 'registrar' in roles:
                registrar = name
            if 'registrant' in roles and org == 'N/A':
                org = name
        return {
            'Domaine': domain,
            'Registrar': registrar,
            'Création': created,
            'Expiration': expires,
            'Dernière MAJ': updated,
            'Pays': 'N/A',
            'Statut': ', '.join(data.get('status', [])[:3]) or 'N/A',
            'Organisation': org,
            '_source': 'RDAP',
        }
    except Exception as e:
        logger.debug('RDAP %s: %s', domain, e)
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

    rdap = _lookup_rdap(domain)
    if rdap and not rdap.get('Erreur'):
        return rdap

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            fut = pool.submit(_lookup_pywhois, domain)
            return fut.result(timeout=WHOIS_TIMEOUT_SEC)
    except FuturesTimeout:
        return {
            'Domaine': domain,
            'Erreur': f'WHOIS timeout ({WHOIS_TIMEOUT_SEC}s) — réessayez ou vérifiez le TLD.',
            '_timeout': True,
        }
    except Exception as e:
        err = str(e)
        if 'timed out' in err.lower():
            err = f'WHOIS timeout — connexion port 43 bloquée ? Utilisez RDAP (réessayez).'
        return {'Domaine': domain, 'Erreur': err, '_timeout': True}
