"""WHOIS domaine enrichi."""
import whois as pywhois


def lookup(domain: str) -> dict:
    domain = domain.strip().lower()
    for prefix in ('http://', 'https://', 'www.'):
        if domain.startswith(prefix):
            domain = domain.replace(prefix, '', 1)
    domain = domain.split('/')[0]
    try:
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
        }
    except Exception as e:
        return {'Domaine': domain, 'Erreur': str(e)}
