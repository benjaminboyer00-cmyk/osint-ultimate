"""Détection quota API et enveloppe fallback scraping (Hunter, Dehashed)."""


def is_quota_error(result: dict | None) -> bool:
    """True si l'API signale quota, rate-limit ou clé manquante bloquante."""
    if not isinstance(result, dict):
        return False
    if result.get('_quota'):
        return True
    msg = ' '.join(
        str(result.get(k, ''))
        for k in ('Erreur', 'error', 'Message', 'message')
    ).lower()
    markers = (
        '429', 'quota', 'rate limit', 'rate-limit', 'too many',
        'limit exceeded', 'upgrade your', 'payment required',
        'forbidden', '402', '403',
    )
    return any(m in msg for m in markers)


def hunter_needs_fallback(result: dict | None) -> bool:
    """Quota Hunter ou réponse vide exploitable → tenter scraping."""
    if not isinstance(result, dict):
        return True
    if is_quota_error(result):
        return True
    if result.get('Erreur') and not result.get('Liste'):
        return True
    emails = result.get('Liste') or []
    count = result.get('Emails trouvés', len(emails))
    return count == 0 and len(emails) == 0


def dehashed_needs_fallback(result: dict | None) -> bool:
    """Uniquement sur quota — pas de scrape si « aucune fuite » (résultat valide)."""
    return is_quota_error(result)


def wrap_scraping_result(base: dict, scraped: dict, *, provider: str) -> dict:
    """Fusionne données scrapées + métadonnées de transparence."""
    out = dict(base)
    out.update(scraped)
    out['_source'] = 'scraping_fallback'
    out['_degraded'] = True
    out['_api_provider'] = provider
    return out
