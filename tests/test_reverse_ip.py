"""Tests reverse IP (domaines sur la même IP)."""
from unittest.mock import patch, MagicMock

import pytest

from extensions import db
from models import User, Entity, EntityLink


def _text_resp(text):
    m = MagicMock()
    m.status_code = 200
    m.text = text
    return m


def test_reverse_ip_parses_domains():
    from connectors import reverse_ip
    with patch('connectors.reverse_ip._resolve_to_ip', return_value='1.2.3.4'), \
         patch('connectors.reverse_ip.safe_get', return_value=_text_resp('a.com\nb.com\nc.com')):
        out = reverse_ip.reverse_ip('1.2.3.4')
    assert out['IP'] == '1.2.3.4'
    assert set(out['Liste']) == {'a.com', 'b.com', 'c.com'}
    assert out['Domaines trouvés'] == 3


def test_reverse_ip_quota_message():
    from connectors import reverse_ip
    with patch('connectors.reverse_ip._resolve_to_ip', return_value='1.2.3.4'), \
         patch('connectors.reverse_ip.safe_get', return_value=_text_resp('API count exceeded - Increase Quota with Membership')):
        out = reverse_ip.reverse_ip('1.2.3.4')
    assert out['Domaines trouvés'] == 0
    assert 'Quota' in out['Message']


def test_reverse_ip_invalid():
    from connectors import reverse_ip
    with patch('connectors.reverse_ip._resolve_to_ip', return_value=None):
        assert 'Erreur' in reverse_ip.reverse_ip('xxx')


def test_registered():
    from scans.registry import SCAN_FUNCTIONS
    assert 'reverse_ip' in SCAN_FUNCTIONS


@pytest.fixture
def user(app):
    with app.app_context():
        u = User(username='u1', email='u1@t.co')
        u.set_password('x')
        db.session.add(u)
        db.session.commit()
        yield u.id


def test_correlation_reverse_ip(app, user):
    from services.correlation import process_scan_correlations
    with app.app_context():
        result = {'IP': '1.2.3.4', 'Liste': ['a.com', 'b.com'], 'Domaines trouvés': 2}
        process_scan_correlations(1, 'reverse_ip', '1.2.3.4', result, user)
        vals = {e.value for e in Entity.query.filter_by(user_id=user).all()}
        assert {'1.2.3.4', 'a.com', 'b.com'} <= vals
        links = EntityLink.query.filter_by(user_id=user, link_type='HEBERGE_SUR').all()
        assert len(links) == 2
