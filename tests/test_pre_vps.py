"""Tests pré-VPS : auth, erreurs, politique mot de passe."""
from services.errors import APIQuotaExceeded, ConnectorError, AccessDeniedError
from services.password_policy import password_strength


def test_password_strength_weak():
    r = password_strength('123')
    assert r['acceptable'] is False


def test_password_strength_okish():
    r = password_strength('MySecurePass2024!')
    assert r['score'] >= 0
    assert 'label' in r


def test_custom_exceptions():
    e = APIQuotaExceeded(provider='shodan')
    assert e.status_code == 429
    assert e.provider == 'shodan'
    c = ConnectorError('fail', provider='x', status_code=500)
    assert isinstance(c, ConnectorError)
    assert isinstance(AccessDeniedError(), Exception)


def test_views_blueprint_import():
    from routes.views import views_bp
    from routes.auth import auth_bp
    assert views_bp.name == 'views'
    assert auth_bp.name == 'auth'
