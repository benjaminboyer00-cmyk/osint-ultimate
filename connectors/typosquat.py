"""Détecteur de domaines sosies (typosquatting) — anti-phishing.

Génère des variantes proches d'un domaine (omission, insertion, substitution
de touches voisines, transposition, doublement, échange de TLD, tiret) puis
vérifie lesquelles **résolvent** (DNS A) — donc potentiellement enregistrées
et actives. Gratuit, sans clé.
"""
from concurrent.futures import ThreadPoolExecutor

from services.url_sanitize import sanitize_domain_host

# Voisins clavier (AZERTY/QWERTY communs) pour les substitutions plausibles.
_ADJ = {
    'a': 'qzs', 'z': 'aesx', 'e': 'zrd', 'r': 'etf', 't': 'ryg', 'y': 'tuh',
    'u': 'yij', 'i': 'uok', 'o': 'ipl', 'p': 'ol', 'q': 'aws', 's': 'awedxz',
    'd': 'serfcx', 'f': 'drtgvc', 'g': 'ftyhbv', 'h': 'gyujnb', 'j': 'huikmn',
    'k': 'jiolm', 'l': 'kop', 'm': 'njk', 'n': 'bhjm', 'b': 'vghn',
    'v': 'cfgb', 'c': 'xdfv', 'x': 'zsdc', 'w': 'qsae',
    '0': 'o9', '1': '2l', '2': '13', '3': '24', '5': 's6', '9': '08',
}
_TLDS = ['com', 'net', 'org', 'co', 'io', 'info', 'online', 'app', 'fr']
_HOMO = {'o': '0', 'l': '1', 'i': '1', 'e': '3', 'a': '4', 's': '5'}


def _variants(name: str, tld: str) -> set[str]:
    out = set()
    n = len(name)
    # omission d'un caractère
    for i in range(n):
        out.add(name[:i] + name[i + 1:] + '.' + tld)
    # transposition de deux caractères adjacents
    for i in range(n - 1):
        out.add(name[:i] + name[i + 1] + name[i] + name[i + 2:] + '.' + tld)
    # doublement
    for i in range(n):
        out.add(name[:i] + name[i] + name[i:] + '.' + tld)
    # substitution touche voisine + homoglyphe
    for i, ch in enumerate(name):
        for repl in _ADJ.get(ch, '') + _HOMO.get(ch, ''):
            out.add(name[:i] + repl + name[i + 1:] + '.' + tld)
    # tiret inséré
    for i in range(1, n):
        out.add(name[:i] + '-' + name[i:] + '.' + tld)
    # échange de TLD (nom identique)
    for t in _TLDS:
        if t != tld:
            out.add(name + '.' + t)
    out.discard(name + '.' + tld)
    return {v for v in out if v.replace('-', '').replace('.', '').isalnum() or '-' in v}


def _resolves(host: str) -> str | None:
    try:
        import dns.resolver
        r = dns.resolver.Resolver()
        r.lifetime = r.timeout = 2.0
        r.resolve(host, 'A')
        return host
    except Exception:
        return None


def find_lookalikes(domain, options=None, max_check: int = 60) -> dict:
    host = sanitize_domain_host((domain or '').strip()) or ''
    if not host or '.' not in host:
        return {'Erreur': 'Domaine invalide.', 'Cible reçue': str(domain)[:120]}
    name, _, tld = host.rpartition('.')
    if not name:
        return {'Erreur': 'Domaine invalide.'}

    variants = sorted(_variants(name.lower(), tld.lower()))[:max_check]
    active = []
    with ThreadPoolExecutor(max_workers=12, thread_name_prefix='typo') as pool:
        for res in pool.map(_resolves, variants):
            if res:
                active.append(res)

    active = sorted(set(active))
    return {
        'Domaine': host,
        'Variantes testées': len(variants),
        'Sosies actifs (résolvent)': len(active),
        'Liste': active,
        'Note': 'Domaines proches qui résolvent en DNS — vérifiez les usurpations potentielles.',
    }
