"""Configuration OSINT Ultimate V4."""
import logging
import os
import secrets
from datetime import timedelta
from pathlib import Path

logger = logging.getLogger(__name__)


def _load_dotenv_file():
    """Charge .env en local (jamais commité). Les variables déjà exportées priment."""
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    env_path = Path(__file__).resolve().parent / '.env'
    if env_path.is_file():
        load_dotenv(env_path, override=False)


_load_dotenv_file()


def normalize_database_url(url):
    """Adapte DATABASE_URL pour SQLAlchemy + Supabase (SSL, driver psycopg2)."""
    if not url:
        return url
    if url.startswith('postgres://'):
        url = url.replace('postgres://', 'postgresql://', 1)
    if url.startswith('postgresql://') and '+psycopg2' not in url and '+psycopg' not in url:
        url = url.replace('postgresql://', 'postgresql+psycopg2://', 1)
    if 'supabase' in url and 'sslmode=' not in url:
        sep = '&' if '?' in url else '?'
        url = f'{url}{sep}sslmode=require'
    return url


def _is_production_deploy(db_url: str) -> bool:
    if os.environ.get('OSINT_PRODUCTION', '').strip().lower() in ('1', 'true', 'yes'):
        return True
    if db_url.startswith('postgresql'):
        return True
    return bool(os.environ.get('SPACE_ID') or os.environ.get('SYSTEM'))


def _resolve_secret_key(production: bool) -> str:
    """Clé stable en prod (env obligatoire) ; fichier local en dev."""
    sk = (os.environ.get('SECRET_KEY') or '').strip()
    if sk:
        return sk
    dev_file = Path(__file__).resolve().parent / '.secret_key_dev'
    if dev_file.is_file():
        return dev_file.read_text(encoding='utf-8').strip()
    if production:
        logger.critical(
            'SECRET_KEY manquant en production — définir dans les secrets (HF/VPS)',
        )
    key = secrets.token_hex(32)
    if not production:
        try:
            dev_file.write_text(key, encoding='utf-8')
            logger.info('SECRET_KEY dev écrite dans %s', dev_file.name)
        except OSError:
            pass
    return key


def build_config():
    _default_db = 'sqlite:////data/osint.db' if os.path.isdir('/data') else 'sqlite:///osint.db'
    db_url = normalize_database_url(os.environ.get('DATABASE_URL', _default_db))
    on_hf = bool(os.environ.get('SPACE_ID') or os.environ.get('SYSTEM'))
    production = _is_production_deploy(db_url)

    def _env_bool(name: str, default: bool) -> bool:
        raw = os.environ.get(name)
        if raw is None:
            return default
        return raw.strip().lower() in ('1', 'true', 'yes', 'on')

    session_secure = _env_bool('SESSION_COOKIE_SECURE', production or on_hf)
    csrf_enabled = _env_bool('WTF_CSRF_ENABLED', production or on_hf)
    force_https = _env_bool('FORCE_HTTPS', production and not on_hf)

    return {
        'SECRET_KEY': _resolve_secret_key(production),
        'OSINT_PRODUCTION': production,
        'SQLALCHEMY_DATABASE_URI': db_url,
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'SQLALCHEMY_ENGINE_OPTIONS': {
            'pool_pre_ping': True,
            'pool_recycle': 300,
            'pool_size': int(os.environ.get('DB_POOL_SIZE', '5')),
            'max_overflow': int(os.environ.get('DB_MAX_OVERFLOW', '2')),
            'pool_timeout': int(os.environ.get('DB_POOL_TIMEOUT', '10')),
            # HA : échec rapide si Supabase injoignable + keepalives anti-coupure
            'connect_args': {
                'connect_timeout': int(os.environ.get('DB_CONNECT_TIMEOUT', '10')),
                'keepalives': 1,
                'keepalives_idle': 30,
                'keepalives_interval': 10,
                'keepalives_count': 5,
                'application_name': 'osint-ultimate',
            },
        } if db_url.startswith('postgresql') else {},
        'SESSION_COOKIE_SAMESITE': 'Lax',
        'SESSION_COOKIE_HTTPONLY': True,
        'SESSION_COOKIE_SECURE': session_secure,
        'PERMANENT_SESSION_LIFETIME': timedelta(days=int(os.environ.get('SESSION_LIFETIME_DAYS', '14'))),
        'REMEMBER_COOKIE_DURATION': timedelta(days=int(os.environ.get('REMEMBER_COOKIE_DAYS', '14'))),
        'REMEMBER_COOKIE_SECURE': session_secure,
        'REMEMBER_COOKIE_HTTPONLY': True,
        'REMEMBER_COOKIE_SAMESITE': 'Lax',
        'WTF_CSRF_ENABLED': csrf_enabled,
        'FORCE_HTTPS': force_https,
        'WTF_CSRF_TIME_LIMIT': None,
        'UPLOAD_FOLDER': 'uploads',
        'MAX_CONTENT_LENGTH': 16 * 1024 * 1024,
        'APP_VERSION': '5.0',
        # Cache long des statiques (URLs versionnées ?v= -> jamais périmé après déploiement)
        'SEND_FILE_MAX_AGE_DEFAULT': int(os.environ.get('STATIC_MAX_AGE', str(60 * 60 * 24 * 365))),
        # Compression gzip + brotli si paquet brotli installé
        'COMPRESS_ALGORITHM': os.environ.get('COMPRESS_ALGORITHM', 'br,gzip'),
        'COMPRESS_BR_LEVEL': int(os.environ.get('COMPRESS_BR_LEVEL', '5')),
        'COMPRESS_MIN_SIZE': 512,
        'COMPRESS_MIMETYPES': [
            'application/json',
            'text/html',
            'text/css',
            'application/javascript',
            'text/javascript',
            'image/svg+xml',
            'application/manifest+json',
        ],
    }
