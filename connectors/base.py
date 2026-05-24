"""Classe de base connecteurs — timeout, retry, cache."""
import logging
from datetime import datetime, timedelta

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from extensions import db
from models import ApiCache
from services.cache import cache_key, get_ttl_hours

logger = logging.getLogger(__name__)


class BaseConnector:
    name = 'base'
    default_timeout = 10
    max_retries = 2
    cache_ttl_hours = 24

    def __init__(self, name=None, default_timeout=None, cache_ttl_hours=None):
        self.name = name or self.name
        if default_timeout is not None:
            self.default_timeout = default_timeout
        if cache_ttl_hours is not None:
            self.cache_ttl_hours = cache_ttl_hours
        self.session = self._create_session(self.max_retries)

    def _create_session(self, max_retries: int):
        session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=['GET', 'POST', 'HEAD'],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount('https://', adapter)
        session.mount('http://', adapter)
        return session

    def _request(self, url, method='GET', timeout=None, options=None, **kwargs):
        timeout = timeout or self.default_timeout
        opts = options or {}
        try:
            fn = self.session.get if method.upper() == 'GET' else self.session.post
            headers = kwargs.pop('headers', {})
            if opts.get('_stealth_mode'):
                import random
                import time
                from services.http_client import USER_AGENTS
                time.sleep(__import__('random').uniform(0.2, 1.2))
                headers.setdefault('User-Agent', random.choice(USER_AGENTS))
            from services.http_client import SSL_VERIFY
            resp = fn(url, timeout=timeout, headers=headers, verify=SSL_VERIFY, **kwargs)
            resp.raise_for_status()
            return resp
        except requests.HTTPError as e:
            status = e.response.status_code if e.response is not None else None
            if status == 429:
                from services.errors import APIQuotaExceeded
                raise APIQuotaExceeded(provider=self.name) from e
            logger.warning('%s: HTTP %s %s', self.name, status, url[:80])
            return None
        except requests.Timeout:
            logger.warning('%s: timeout %s', self.name, url[:80])
            return None
        except requests.RequestException as e:
            logger.warning('%s: %s', self.name, e)
            return None

    def _cache_row(self, provider: str, query: str):
        ck = cache_key(provider, query)
        return db.session.query(ApiCache).filter_by(cache_key=ck).first()

    def get_cached_or_fetch(self, query: str, fetch_func, force_refresh=False, provider=None):
        """
        Retourne (data, source) — source: cache | live | cache_expired | failed | timeout
        """
        provider = provider or self.name
        from services.circuit_breaker import is_open, record_failure, record_success, breaker_open_response
        if is_open(provider):
            return breaker_open_response(provider), 'circuit_open'

        ck = cache_key(provider, query)
        row = self._cache_row(provider, query)
        ttl = get_ttl_hours(provider) or self.cache_ttl_hours

        if row and not force_refresh:
            age = datetime.utcnow() - (row.created_at or datetime.utcnow())
            if age < timedelta(hours=ttl):
                try:
                    import json
                    return json.loads(row.payload), 'cache'
                except Exception:
                    pass

        try:
            data = fetch_func()
            if data is None:
                record_failure(provider)
                if row:
                    import json
                    try:
                        return json.loads(row.payload), 'cache_expired'
                    except Exception:
                        pass
                return {'_timeout': True, 'Message': 'Service lent ou indisponible'}, 'timeout'
            if isinstance(data, dict) and data.get('_timeout'):
                record_failure(provider)
                if row:
                    import json
                    try:
                        return json.loads(row.payload), 'cache_expired'
                    except Exception:
                        pass
                return data, 'timeout'
            self._save_cache(provider, query, ck, row, data)
            record_success(provider)
            return data, 'live'
        except Exception as e:
            from services.errors import APIQuotaExceeded, ConnectorError
            if isinstance(e, APIQuotaExceeded):
                logger.warning('%s quota: %s', self.name, e)
            elif isinstance(e, ConnectorError):
                logger.warning('%s connector: %s', self.name, e)
            else:
                logger.error('%s fetch: %s', self.name, e)
            record_failure(provider)
            if row:
                import json
                try:
                    return json.loads(row.payload), 'cache_expired'
                except Exception:
                    pass
            return {'Erreur': str(e)}, 'failed'

    def _save_cache(self, provider, query, ck, row, data):
        import json
        from services.cache import set_cached
        set_cached(provider, query, data, ttl_hours=get_ttl_hours(provider))
