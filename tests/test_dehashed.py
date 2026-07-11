"""Tests connecteur dehashed (fuites de données — données sensibles)."""
from unittest.mock import patch, MagicMock

from connectors import dehashed


def _resp(status=200, payload=None):
    m = MagicMock()
    m.status_code = status
    m.json.return_value = payload if payload is not None else {}
    return m


def test_no_key_no_http():
    out = dehashed.search('a@b.com', '')
    assert 'Erreur' in out and 'clé' in out['Erreur'].lower()


def test_timeout_handled():
    with patch('connectors.dehashed.get_cached', return_value=None), \
         patch('connectors.dehashed.safe_get', return_value=None):
        out = dehashed.search('a@b.com', 'key')
    assert out.get('_timeout') and 'Erreur' in out


def test_401_invalid_credentials():
    with patch('connectors.dehashed.get_cached', return_value=None), \
         patch('connectors.dehashed.safe_get', return_value=_resp(401)):
        out = dehashed.search('a@b.com', 'key')
    assert 'invalides' in out['Erreur'].lower()


def test_429_quota_flagged():
    with patch('connectors.dehashed.get_cached', return_value=None), \
         patch('connectors.dehashed.safe_get', return_value=_resp(429)):
        out = dehashed.search('a@b.com', 'key')
    assert out.get('_quota') is True


def test_cache_hit_returns_flagged():
    with patch('connectors.dehashed.get_cached', return_value={'Fuites trouvées': 3, 'Entrées': []}):
        out = dehashed.search('a@b.com', 'key')
    assert out['_cached'] is True and out['Fuites trouvées'] == 3


def test_parses_entries_and_basic_auth_with_email():
    payload = {'entries': [
        {'email': 'x@y.com', 'username': 'xx', 'database_name': 'BreachDB', 'breach_date': '2021'},
        'garbage',  # ignoré (pas un dict)
    ]}
    captured = {}

    def fake_get(url, headers=None, **kw):
        captured['url'] = url
        captured['headers'] = headers
        return _resp(200, payload)

    with patch('connectors.dehashed.get_cached', return_value=None), \
         patch('connectors.dehashed.set_cached'), \
         patch('connectors.dehashed.get_ttl_hours', return_value=0), \
         patch('connectors.dehashed.safe_get', side_effect=fake_get):
        out = dehashed.search('x@y.com', 'key', email='me@x.com')

    assert out['Fuites trouvées'] == 1
    assert out['Entrées'][0]['Email'] == 'x@y.com'
    assert out['Entrées'][0]['Base'] == 'BreachDB'
    assert captured['headers']['Authorization'].startswith('Basic ')  # email -> Basic


def test_bearer_auth_without_email():
    captured = {}

    def fake_get(url, headers=None, **kw):
        captured['headers'] = headers
        return _resp(200, {'entries': []})

    with patch('connectors.dehashed.get_cached', return_value=None), \
         patch('connectors.dehashed.set_cached'), \
         patch('connectors.dehashed.get_ttl_hours', return_value=0), \
         patch('connectors.dehashed.safe_get', side_effect=fake_get):
        dehashed.search('someuser', 'key')

    assert captured['headers']['Authorization'].startswith('Bearer ')
