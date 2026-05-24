"""Cache Flask (fragments) — Redis si dispo, sinon mémoire."""
import logging
import os

logger = logging.getLogger(__name__)
cache = None


def init_cache(app):
    global cache
    from flask_caching import Cache

    redis_url = os.environ.get('REDIS_URL') or os.environ.get('CELERY_BROKER_URL')
    if redis_url:
        config = {
            'CACHE_TYPE': 'RedisCache',
            'CACHE_REDIS_URL': redis_url,
            'CACHE_DEFAULT_TIMEOUT': 300,
        }
    else:
        config = {
            'CACHE_TYPE': 'SimpleCache',
            'CACHE_DEFAULT_TIMEOUT': 120,
        }
    app.config.update(config)
    cache = Cache(app)
    logger.info('Flask-Caching: %s', config['CACHE_TYPE'])
    return cache
