"""Modules de scan additionnels (connecteurs V5)."""
from connectors.hunter import search_domain as hunter_domain
from connectors.dehashed import search as dehashed_search
from connectors.epieos import search as epieos_search
from connectors.wayback import search_url as wayback_search
from connectors.whois_domain import lookup as whois_lookup
from connectors.messaging import check_phone_presence


def _opt(options, key, env_name=''):
    import os
    return (options or {}).get(key) or os.environ.get(env_name, '')


def scan_hunter(target, options=None):
    key = _opt(options, '_hunter_key', 'HUNTER_API_KEY')
    domain = target.strip()
    if '@' in domain:
        domain = domain.split('@')[1]
    return hunter_domain(domain, key, options)


def scan_dehashed(target, options=None):
    key = _opt(options, '_dehashed_key', 'DEHASHED_API_KEY')
    email = _opt(options, '_dehashed_email', 'DEHASHED_EMAIL')
    return dehashed_search(target, key, email, options)


def scan_epieos(target, options=None):
    key = _opt(options, '_epieos_key', 'EPIEOS_API_KEY')
    return epieos_search(target, key, options)


def scan_wayback(target, options=None):
    return wayback_search(target, options)


def scan_whois(target, options=None):
    return whois_lookup(target)


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
    'multi': scan_multi,
}
