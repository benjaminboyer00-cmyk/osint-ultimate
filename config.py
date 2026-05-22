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
        'SESSION_COOKIE_SECURE': os.environ.get(
            'SESSION_COOKIE_SECURE', 'true' if on_hf else 'false'
        ).lower() == 'true',
        'UPLOAD_FOLDER': 'uploads',
        'MAX_CONTENT_LENGTH': 16 * 1024 * 1024,
        'APP_VERSION': '4.2',
    }
