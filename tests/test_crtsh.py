"""Tests module sous-domaines (crt.sh) + corrélation."""
from unittest.mock import patch, MagicMock

import pytest

from extensions import db
from models import User, Entity, EntityLink


def _resp(payload):
    m = MagicMock()
    m.status_code = 200
    m.json.return_value = payload
    return m


def test_parse_subdomains():
    from connectors import crtsh
    payload = [
        {'name_value': 'www.example.com\n*.example.com'},
        {'name_value': 'api.example.com'},
        {'name_value': 'mail.example.com\nwww.example.com'},   # doublon
        {'name_value': 'other.org'},                            # hors domaine
    ]
    with patch('connectors.crtsh.safe_get', return_value=_resp(payload)):
        out = crtsh.search_subdomains('example.com')
    assert out['Domaine'] == 'example.com'
    assert set(out['Liste']) == {'www.example.com', 'api.example.com', 'mail.example.com'}
    assert out['Sous-domaines trouvés'] == 3


def test_invalid_domain():
    from connectors import crtsh
    out = crtsh.search_subdomains('pas un domaine')
    assert 'Erreur' in out


def test_module_registered():
    from scans.registry import SCAN_FUNCTIONS
    assert 'subdomains' in SCAN_FUNCTIONS
    assert callable(SCAN_FUNCTIONS['subdomains'])


@pytest.fixture
def user(app):
    with app.app_context():
        u = User(username='u1', email='u1@t.co')
        u.set_password('x')
        db.session.add(u)
        db.session.commit()
        yield u.id


def test_correlation_creates_subdomain_nodes(app, user):
    from services.correlation import process_scan_correlations
    with app.app_context():
        # 'www.*' est normalisé vers l'apex (par conception) -> on teste des
        # sous-domaines distincts.
        result = {
            'Domaine': 'example.com',
            'Liste': ['api.example.com', 'mail.example.com', 'blog.example.com'],
            'Sous-domaines trouvés': 3,
        }
        process_scan_correlations(1, 'subdomains', 'example.com', result, user)
        vals = {e.value for e in Entity.query.filter_by(user_id=user).all()}
        assert 'example.com' in vals
        assert {'api.example.com', 'mail.example.com', 'blog.example.com'} <= vals
        links = EntityLink.query.filter_by(user_id=user, link_type='SOUS_DOMAINE').all()
        assert len(links) == 3
