"""Catalogue marketplace des connecteurs OSINT."""
from __future__ import annotations

# Métadonnées enrichies (indépendant de l'implémentation)
CATALOG = [
    {
        'id': 'email', 'name': 'Analyse email', 'category': 'identité',
        'description': 'MX, SPF, DMARC, fuites HIBP, validation SMTP.',
        'inputs': ['email'], 'api_key': None, 'status': 'active', 'ttl_h': 24,
    },
    {
        'id': 'dehashed', 'name': 'Dehashed', 'category': 'fuites',
        'description': 'Recherche dans les fuites de données (email, pseudo, téléphone).',
        'inputs': ['email', 'pseudo', 'phone'], 'api_key': 'dehashed', 'status': 'active', 'ttl_h': 48,
    },
    {
        'id': 'hunter', 'name': 'Hunter.io', 'category': 'identité',
        'description': 'Emails professionnels associés à un domaine.',
        'inputs': ['domain', 'email'], 'api_key': 'hunter', 'status': 'active', 'ttl_h': 72,
    },
    {
        'id': 'epieos', 'name': 'Epieos', 'category': 'identité',
        'description': 'Enrichissement comptes Google / Microsoft liés à un email.',
        'inputs': ['email'], 'api_key': 'epieos', 'status': 'active', 'ttl_h': 48,
    },
    {
        'id': 'sherlock', 'name': 'Sherlock', 'category': 'réseaux',
        'description': 'Pseudo recherché sur 300+ plateformes publiques.',
        'inputs': ['pseudo', 'username'], 'api_key': None, 'status': 'active', 'ttl_h': 24,
    },
    {
        'id': 'github', 'name': 'GitHub', 'category': 'réseaux',
        'description': 'Profil et dépôts publics GitHub.',
        'inputs': ['pseudo'], 'api_key': None, 'status': 'active', 'ttl_h': 24,
    },
    {
        'id': 'phone', 'name': 'Téléphone', 'category': 'identité',
        'description': 'Validation E.164, opérateur, géolocalisation approximative.',
        'inputs': ['phone'], 'api_key': None, 'status': 'active', 'ttl_h': 24,
    },
    {
        'id': 'messaging', 'name': 'Messageries', 'category': 'réseaux',
        'description': 'Présence WhatsApp / Telegram (indicateurs publics).',
        'inputs': ['phone'], 'api_key': None, 'status': 'active', 'ttl_h': 12,
    },
    {
        'id': 'site', 'name': 'Analyse site', 'category': 'infrastructure',
        'description': 'DNS, HTTP, headers sécurité, technologies.',
        'inputs': ['domain', 'url'], 'api_key': None, 'status': 'active', 'ttl_h': 24,
    },
    {
        'id': 'whois', 'name': 'WHOIS', 'category': 'infrastructure',
        'description': 'Registre domaine, dates, contacts publics.',
        'inputs': ['domain'], 'api_key': None, 'status': 'active', 'ttl_h': 168,
    },
    {
        'id': 'wayback', 'name': 'Wayback Machine', 'category': 'infrastructure',
        'description': 'Snapshots historiques d\'URL via Internet Archive.',
        'inputs': ['domain', 'url'], 'api_key': None, 'status': 'active', 'ttl_h': 72,
    },
    {
        'id': 'ip', 'name': 'Analyse IP', 'category': 'infrastructure',
        'description': 'Géolocalisation, Shodan (si clé), ports ouverts.',
        'inputs': ['ip'], 'api_key': 'shodan', 'status': 'active', 'ttl_h': 24,
    },
    {
        'id': 'pseudo', 'name': 'Pseudo classique', 'category': 'réseaux',
        'description': 'Recherche pseudo sur réseaux sociaux majeurs.',
        'inputs': ['pseudo'], 'api_key': None, 'status': 'active', 'ttl_h': 24,
    },
    {
        'id': 'instagram', 'name': 'Instagram', 'category': 'réseaux',
        'description': 'Profil public Instagram.', 'inputs': ['pseudo'],
        'api_key': None, 'status': 'beta', 'ttl_h': 12,
    },
    {
        'id': 'twitter', 'name': 'X / Twitter', 'category': 'réseaux',
        'description': 'Profil public X.', 'inputs': ['pseudo'],
        'api_key': None, 'status': 'beta', 'ttl_h': 12,
    },
    {
        'id': 'linkedin', 'name': 'LinkedIn', 'category': 'réseaux',
        'description': 'Profil public LinkedIn.', 'inputs': ['pseudo'],
        'api_key': None, 'status': 'beta', 'ttl_h': 12,
    },
    {
        'id': 'otx', 'name': 'AlienVault OTX', 'category': 'menace',
        'description': 'Indicateurs de compromission (IP, domaine, hash).',
        'inputs': ['ip', 'domain'], 'api_key': 'otx', 'status': 'active', 'ttl_h': 6,
    },
    {
        'id': 'urlhaus', 'name': 'URLhaus', 'category': 'menace',
        'description': 'URLs malveillantes signalées (abuse.ch).',
        'inputs': ['domain', 'url'], 'api_key': None, 'status': 'active', 'ttl_h': 6,
    },
    {
        'id': 'multi', 'name': 'Multi-scan', 'category': 'orchestration',
        'description': 'Orchestration parallèle de plusieurs modules.',
        'inputs': ['*'], 'api_key': None, 'status': 'active', 'ttl_h': 0,
    },
]


def get_catalog(installed_only: bool = True) -> list[dict]:
    """Retourne le catalogue avec indicateur installed selon SCAN_FUNCTIONS."""
    try:
        from app import SCAN_FUNCTIONS
        available = set(SCAN_FUNCTIONS.keys())
    except Exception:
        available = {c['id'] for c in CATALOG}

    out = []
    for entry in CATALOG:
        row = dict(entry)
        row['installed'] = entry['id'] in available
        if installed_only and not row['installed']:
            continue
        out.append(row)
    return out


def get_connector(connector_id: str) -> dict | None:
    for c in CATALOG:
        if c['id'] == connector_id:
            row = dict(c)
            try:
                from app import SCAN_FUNCTIONS
                row['installed'] = connector_id in SCAN_FUNCTIONS
            except Exception:
                row['installed'] = False
            return row
    return None
