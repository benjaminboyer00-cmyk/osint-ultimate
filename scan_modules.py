"""Modules de scan additionnels (connecteurs V5)."""
from connectors.hunter import search_domain as hunter_domain
from connectors.dehashed import search as dehashed_search
from connectors.epieos import search as epieos_search
from connectors.wayback import search_url as wayback_search
from connectors.whois_domain import lookup as whois_lookup
from connectors.messaging import check_phone_presence
from connectors.otx import search as otx_search
from connectors.urlhaus import search as urlhaus_search
from connectors.dorking import search as dorking_search


def _opt(options, key, env_name=''):
    import os
    return (options or {}).get(key) or os.environ.get(env_name, '')


def scan_hunter(target, options=None):
    from connectors.scraper_fallback import fallback_scrape_emails
    from services.quota_fallback import hunter_needs_fallback, wrap_scraping_result

    from services.url_sanitize import sanitize_domain_host

    key = _opt(options, '_hunter_key', 'HUNTER_API_KEY')
    domain = target.strip()
    if '@' in domain:
        domain = domain.split('@')[1]
    domain = sanitize_domain_host(domain) or ''
    if not domain:
        return {
            'Erreur': 'Cible invalide pour Hunter (domaine attendu, pas un numéro ou texte libre).',
            'Cible reçue': target[:120],
        }

    result = hunter_domain(domain, key, options)
    if not hunter_needs_fallback(result):
        return result

    from services.scrape_policy import scrape_fallback_allowed
    if not scrape_fallback_allowed(options):
        if isinstance(result, dict):
            result['Message'] = (
                'Quota API atteint. Fallback scraping désactivé (Paramètres → OPSEC).'
            )
        return result

    scraped = fallback_scrape_emails(domain, options)
    msg = (
        'Quota API Hunter atteint ou réponse vide. '
        'Emails extraits via recherche publique (DuckDuckGo / cloudscraper).'
    )
    if not scraped:
        msg += ' Aucun email public trouvé pour ce domaine — essayez une recherche manuelle ou une clé Hunter valide.'
    return wrap_scraping_result(
        {
            'Domaine': domain,
            'Organisation': result.get('Organisation') if isinstance(result, dict) else None,
            'Emails trouvés': len(scraped),
            'Liste': scraped,
            'Message': msg,
        },
        {},
        provider='hunter',
    )


def scan_dehashed(target, options=None):
    from connectors.scraper_fallback import fallback_scrape_dehashed_hints
    from services.quota_fallback import dehashed_needs_fallback, wrap_scraping_result

    key = _opt(options, '_dehashed_key', 'DEHASHED_API_KEY')
    email = _opt(options, '_dehashed_email', 'DEHASHED_EMAIL')
    result = dehashed_search(target, key, email, options)

    if not dehashed_needs_fallback(result):
        return result

    from services.scrape_policy import scrape_fallback_allowed
    if not scrape_fallback_allowed(options):
        if isinstance(result, dict):
            result['Message'] = (
                'Quota API atteint. Fallback scraping désactivé (Paramètres → OPSEC).'
            )
        return result

    hints = fallback_scrape_dehashed_hints(target, options)
    return wrap_scraping_result(
        {
            'Requête': target.strip(),
            'Fuites trouvées': 0,
            'Entrées': hints or ['Aucun indice public trouvé (scraping)'],
            'Message': (
                'Quota API Dehashed atteint. '
                'Indices publics uniquement (pas de base de fuites certifiée).'
            ),
        },
        {},
        provider='dehashed',
    )


def scan_epieos(target, options=None):
    key = _opt(options, '_epieos_key', 'EPIEOS_API_KEY')
    return epieos_search(target, key, options)


def scan_wayback(target, options=None):
    return wayback_search(target, options)


def scan_whois(target, options=None):
    return whois_lookup(target)


def scan_otx(target, options=None):
    key = _opt(options, '_otx_key', 'OTX_API_KEY')
    return otx_search(target, key, options)


def scan_urlhaus(target, options=None):
    return urlhaus_search(target, options)


def scan_messaging(target, options=None):
    phone = target.strip()
    if not phone.startswith('+'):
        try:
            import phonenumbers
            p = phonenumbers.parse(phone, 'FR')
            phone = phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.E164)
        except Exception:
            pass
    return check_phone_presence(phone, options)


def scan_dorking(target, options=None):
    """Recherche profonde par dorks (DuckDuckGo HTML)."""
    return dorking_search(target, options or {})


def scan_subdomains(target, options=None):
    """Sous-domaines via Certificate Transparency (crt.sh) — gratuit, sans clé."""
    from connectors.crtsh import search_subdomains
    return search_subdomains(target, options)


def scan_multi(target, options=None):
    """Scan parallèle multi-modules (Expert / Express)."""
    from services.scanner import launch_multi_scan
    opts = options or {}
    mode = opts.get('_scan_mode', 'expert')
    category = opts.get('_category')
    modules = opts.get('_modules')
    return launch_multi_scan(
        target, options=opts, mode=mode,
        modules=modules, category=category,
    )


EXTRA_SCAN_FUNCTIONS = {
    'hunter': scan_hunter,
    'dehashed': scan_dehashed,
    'epieos': scan_epieos,
    'wayback': scan_wayback,
    'whois': scan_whois,
    'messaging': scan_messaging,
    'otx': scan_otx,
    'urlhaus': scan_urlhaus,
    'dorking': scan_dorking,
    'subdomains': scan_subdomains,
    'multi': scan_multi,
}
