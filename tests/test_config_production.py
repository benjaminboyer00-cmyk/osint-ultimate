"""Configuration production / SECRET_KEY stable."""
import os
from unittest.mock import patch

from config import _resolve_secret_key, build_config


def test_secret_key_from_env():
    with patch.dict(os.environ, {'SECRET_KEY': 'fixed-test-key-64charsxxxxxxxxxxxxxxxxxxxx'}, clear=False):
        assert _resolve_secret_key(True) == 'fixed-test-key-64charsxxxxxxxxxxxxxxxxxxxx'


def test_production_flags_with_postgres():
    with patch.dict(
        os.environ,
        {
            'DATABASE_URL': 'postgresql://u:p@localhost/db',
            'SECRET_KEY': 'x' * 32,
            'SESSION_COOKIE_SECURE': 'true',
            'WTF_CSRF_ENABLED': 'true',
        },
        clear=False,
    ):
        cfg = build_config()
    assert cfg['OSINT_PRODUCTION'] is True
    assert cfg['SESSION_COOKIE_SECURE'] is True
    assert cfg['WTF_CSRF_ENABLED'] is True
