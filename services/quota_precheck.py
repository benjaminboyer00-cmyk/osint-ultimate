"""Vérification proactive des quotas API (cache court)."""
import time

from services.quota_monitor import check_hunter

_CACHE: dict[str, tuple[float, dict]] = {}
_TTL_SEC = 300


def _cached(provider: str, api_key: str, checker) -> dict:
    if not api_key:
        return {'status': 'unconfigured'}
    key = f'{provider}:{api_key[:12]}'
    now = time.time()
    hit = _CACHE.get(key)
    if hit and now - hit[0] < _TTL_SEC:
        return hit[1]
    result = checker(api_key)
    _CACHE[key] = (now, result)
    return result


def hunter_quota_blocked(api_key: str) -> str | None:
    """
    Retourne un message d'erreur si le quota Hunter semble épuisé, sinon None.
    """
    info = _cached('hunter', api_key, check_hunter)
    if info.get('status') == 'error':
        return info.get('message') or 'Quota Hunter indisponible'
    avail = info.get('available')
    if avail is not None and avail <= 0:
        return 'Quota Hunter épuisé — vérifiez votre plan'
    if info.get('status') == 'warning' and avail is not None and avail < 3:
        return None  # avertissement seulement, pas de blocage
    return None
