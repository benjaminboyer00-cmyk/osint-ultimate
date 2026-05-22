"""Politique de fallback scraping (OPSEC / conformité)."""
import os


def scrape_fallback_allowed(options: dict | None) -> bool:
    """
    False si l'utilisateur ou l'admin a désactivé le scraping de secours.
    options['_scrape_fallback'] est injecté par scan_runner depuis User.scrape_fallback_enabled.
    """
    opts = options or {}
    if opts.get('_scrape_fallback') is False:
        return False
    env = (os.environ.get('SCRAPE_FALLBACK_ENABLED') or 'true').strip().lower()
    if env in ('0', 'false', 'no', 'off'):
        return False
    return True


def cloudflare_scrape_allowed(options: dict | None) -> bool:
    """cloudscraper uniquement si fallback global autorisé."""
    if not scrape_fallback_allowed(options):
        return False
    env = (os.environ.get('CLOUDSCRAPER_ENABLED') or 'true').strip().lower()
    if env in ('0', 'false', 'no', 'off'):
        return False
    return True
