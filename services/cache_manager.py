"""
Cache distribué Redis (optionnel) avec repli sur ApiCache SQL + mémoire process.
Clés : lookup:{provider}:{sha256(query)}
"""
import hashlib
import json
import logging
import os
from datetime import timedelta

logger = logging.getLogger(__name__)

_redis_client = None
_redis_checked = False

# TTL secondes par type (surcharge env CACHE_TTL_SEC_<PROVIDER>)
TTL_SECONDS = {
    'whois': 3600,
    'wayback': 86400,
    'hunter': 86400,
    'dehashed': 86400,
    'hibp': 86400,
    'dorking': 43200,
    'instagram': 300,
    'twitter': 300,
    'tiktok': 300,
    'github': 3600,
    'shodan': 3600,
    'groq': 0,
    'narrative': 7200,
    'default': 3600,
}


def redis_available() -> bool:
    return get_redis() is not None


def get_redis():
    global _redis_client, _redis_checked
    if _redis_checked:
        return _redis_client if _redis_client is not False else None
    _redis_checked = True
    url = os.environ.get('REDIS_URL') or os.environ.get('CELERY_BROKER_URL')
    if not url:
        _redis_client = False
        return None
    try:
        import redis
        client = redis.from_url(url, decode_responses=True, socket_connect_timeout=2)
        client.ping()
        _redis_client = client
        logger.info('Cache Redis connecté')
        return client
    except Exception as e:
        logger.warning('Redis cache indisponible: %s', e)
        _redis_client = False
        return None


def _redis_key(provider: str, query: str) -> str:
    h = hashlib.sha256(f'{provider}:{query}'.lower().strip().encode()).hexdigest()
    return f'lookup:{provider}:{h}'


def ttl_seconds(provider: str) -> int:
    env_key = f'CACHE_TTL_SEC_{provider.upper()}'
    if os.environ.get(env_key):
        try:
            return int(os.environ[env_key])
        except ValueError:
            pass
    from services.cache import get_ttl_hours
    hours = get_ttl_hours(provider)
    if hours <= 0:
        return 0
    return TTL_SECONDS.get(provider, TTL_SECONDS['default']) or hours * 3600


def cache_get(provider: str, query: str) -> dict | None:
    """Lecture Redis uniquement (SQL géré par services.cache)."""
    r = get_redis()
    if not r:
        return None
    try:
        raw = r.get(_redis_key(provider, query))
        if raw:
            return json.loads(raw)
    except Exception as e:
        logger.warning('Redis GET %s: %s', provider, e)
    return None


def cache_set(provider: str, query: str, data: dict, ttl_sec: int | None = None) -> None:
    if ttl_sec is None:
        ttl_sec = ttl_seconds(provider)
    if ttl_sec <= 0:
        return
    payload = json.dumps(data, ensure_ascii=False, default=str)
    r = get_redis()
    if r:
        try:
            r.setex(_redis_key(provider, query), ttl_sec, payload)
        except Exception as e:
            logger.warning('Redis SET %s: %s', provider, e)


def narrative_cache_key(entity_id: int, owner_id: int, data_hash: str) -> str:
    return f'narrative:{owner_id}:{entity_id}:{data_hash}'


def get_narrative_cached(entity_id: int, owner_id: int, data_hash: str) -> dict | None:
    r = get_redis()
    if not r:
        return None
    try:
        raw = r.get(narrative_cache_key(entity_id, owner_id, data_hash))
        return json.loads(raw) if raw else None
    except Exception:
        return None


def set_narrative_cached(entity_id: int, owner_id: int, data_hash: str, payload: dict) -> None:
    r = get_redis()
    if not r:
        return
    try:
        r.setex(
            narrative_cache_key(entity_id, owner_id, data_hash),
            ttl_seconds('narrative'),
            json.dumps(payload, ensure_ascii=False, default=str),
        )
    except Exception as e:
        logger.warning('Redis narrative cache: %s', e)
