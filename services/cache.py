"""Cache TTL pour réponses API externes."""
import json
import hashlib
from datetime import datetime, timedelta
from extensions import db
from models import ApiCache

import os

DEFAULT_TTL_HOURS = 24

# TTL par connecteur (heures) — surcharge via CACHE_TTL_<PROVIDER>
PROVIDER_TTL = {
    'hunter': 48,
    'dehashed': 72,
    'wayback': 168,
    'shodan': 24,
    'groq': 0,
    'hibp': 48,
    'dorking': 12,
}


def get_ttl_hours(provider: str) -> int:
    env_key = f'CACHE_TTL_{provider.upper()}'
    if os.environ.get(env_key):
        try:
            return int(os.environ[env_key])
        except ValueError:
            pass
    return PROVIDER_TTL.get(provider, DEFAULT_TTL_HOURS)


def cache_key(provider: str, query: str) -> str:
    raw = f'{provider}:{query}'.lower().strip()
    return hashlib.sha256(raw.encode()).hexdigest()


def _cache_row(cache_key_hash: str):
    """ApiCache a une colonne `query` qui masque Model.query — utiliser db.session."""
    return db.session.query(ApiCache).filter_by(cache_key=cache_key_hash).first()


def get_cached(provider: str, query: str) -> dict | None:
    ck = cache_key(provider, query)
    try:
        row = _cache_row(ck)
        if not row or row.expires_at < datetime.utcnow():
            return None
        return json.loads(row.payload)
    except Exception:
        db.session.rollback()
        return None


def set_cached(provider: str, query: str, data: dict, ttl_hours: int | None = None):
    if ttl_hours is None:
        ttl_hours = get_ttl_hours(provider)
    if ttl_hours <= 0:
        return
    ck = cache_key(provider, query)
    try:
        row = _cache_row(ck)
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
    except Exception:
        db.session.rollback()
