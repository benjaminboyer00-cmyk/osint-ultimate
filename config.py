"""Configuration OSINT Ultimate V4."""
import os


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


def build_config():
    _default_db = 'sqlite:////data/osint.db' if os.path.isdir('/data') else 'sqlite:///osint.db'
    db_url = normalize_database_url(os.environ.get('DATABASE_URL', _default_db))
    on_hf = bool(os.environ.get('SPACE_ID') or os.environ.get('SYSTEM'))

    return {
        'SECRET_KEY': os.environ.get('SECRET_KEY', 'change-me-' + os.urandom(16).hex()),
        'SQLALCHEMY_DATABASE_URI': db_url,
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'SQLALCHEMY_ENGINE_OPTIONS': {
            'pool_pre_ping': True,
            'pool_recycle': 300,
        } if db_url.startswith('postgresql') else {},
        'SESSION_COOKIE_SAMESITE': 'Lax',
        'SESSION_COOKIE_HTTPONLY': True,
        'SESSION_COOKIE_SECURE': os.environ.get(
            'SESSION_COOKIE_SECURE', 'true' if on_hf else 'false'
        ).lower() == 'true',
        'WTF_CSRF_ENABLED': os.environ.get(
            'WTF_CSRF_ENABLED', 'true' if on_hf else 'false',
        ).lower() == 'true',
        'WTF_CSRF_TIME_LIMIT': None,
        'UPLOAD_FOLDER': 'uploads',
        'MAX_CONTENT_LENGTH': 16 * 1024 * 1024,
        'APP_VERSION': '5.0',
        # Compression gzip + brotli si paquet brotli installé
        'COMPRESS_ALGORITHM': os.environ.get('COMPRESS_ALGORITHM', 'br,gzip'),
        'COMPRESS_BR_LEVEL': int(os.environ.get('COMPRESS_BR_LEVEL', '5')),
        'COMPRESS_MIN_SIZE': 512,
        'COMPRESS_MIMETYPES': [
            'application/json',
            'text/html',
            'text/css',
            'application/javascript',
        ],
    }
