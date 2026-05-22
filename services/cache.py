"""Cache TTL pour réponses API externes."""
import json
import hashlib
from datetime import datetime, timedelta
from extensions import db
from models import ApiCache

DEFAULT_TTL_HOURS = 24


def cache_key(provider: str, query: str) -> str:
    raw = f'{provider}:{query}'.lower().strip()
    return hashlib.sha256(raw.encode()).hexdigest()


def get_cached(provider: str, query: str) -> dict | None:
    ck = cache_key(provider, query)
    row = ApiCache.query.filter_by(cache_key=ck).first()
    if not row or row.expires_at < datetime.utcnow():
        return None
    try:
        return json.loads(row.payload)
    except Exception:
        return None


def set_cached(provider: str, query: str, data: dict, ttl_hours: int = DEFAULT_TTL_HOURS):
    ck = cache_key(provider, query)
    row = ApiCache.query.filter_by(cache_key=ck).first()
    exp = datetime.utcnow() + timedelta(hours=ttl_hours)
    payload = json.dumps(data, ensure_ascii=False, default=str)
    if row:
        row.payload = payload
        row.expires_at = exp
    else:
        db.session.add(ApiCache(
            provider=provider,
            cache_key=ck,
            query=query[:500],
            payload=payload,
            expires_at=exp,
        ))
    db.session.commit()
