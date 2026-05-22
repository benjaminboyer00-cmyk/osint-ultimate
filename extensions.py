"""Extensions Flask partagées (évite les imports circulaires avec Alembic)."""
import os

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()


def _api_rate_limit_key():
    """Clé rate-limit API : token header (avant chargement de request.api_user)."""
    from flask import request
    key = (request.headers.get('X-API-Key') or '').strip()
    if not key:
        auth = request.headers.get('Authorization') or ''
        if auth.lower().startswith('bearer '):
            key = auth[7:].strip()
    if key:
        return f'api:{key[:32]}'
    return get_remote_address()


limiter = Limiter(
    key_func=_api_rate_limit_key,
    default_limits=[],
    storage_uri=os.environ.get('RATELIMIT_STORAGE_URI', 'memory://'),
)
