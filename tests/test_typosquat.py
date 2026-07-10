"""Tests détecteur de domaines sosies (typosquatting)."""
from unittest.mock import patch

import pytest

from extensions import db
from models import User, Entity, EntityLink


def test_variants_generation():
    from connectors import typosquat
    v = typosquat._variants('google', 'com')
    # omission, transposition, TLD swap présents
    assert 'gogle.com' in v          # omission du 'o'
    assert 'google.net' in v         # échange de TLD
    assert 'google.com' not in v     # jamais le domaine lui-même
    assert len(v) > 20


def test_find_lookalikes_filters_resolving():
    from connectors import typosquat
    # simule : seuls 'gogle.com' et 'google.net' résolvent
    def fake_resolve(host):
        return host if host in ('gogle.com', 'google.net') else None
    with patch('connectors.typosquat._resolves', side_effect=fake_resolve):
        out = typosquat.find_lookalikes('google.com', max_check=200)
    assert out['Domaine'] == 'google.com'
    assert set(out['Liste']) == {'gogle.com', 'google.net'}
    assert out['Sosies actifs (résolvent)'] == 2


def test_invalid_domain():
    from connectors import typosquat
    assert 'Erreur' in typosquat.find_lookalikes('pas-un-domaine')


def test_registered():
    from scans.registry import SCAN_FUNCTIONS
    assert 'typosquat' in SCAN_FUNCTIONS


@pytest.fixture
def user(app):
    with app.app_context():
        u = User(username='u1', email='u1@t.co')
        u.set_password('x')
        db.session.add(u)
        db.session.commit()
        yield u.id


def test_correlation_lookalikes(app, user):
    from services.correlation import process_scan_correlations
    with app.app_context():
        result = {'Domaine': 'google.com', 'Liste': ['gogle.com', 'googie.com'],
                  'Sosies actifs (résolvent)': 2}
        process_scan_correlations(1, 'typosquat', 'google.com', result, user)
        vals = {e.value for e in Entity.query.filter_by(user_id=user).all()}
        assert {'google.com', 'gogle.com', 'googie.com'} <= vals
        links = EntityLink.query.filter_by(user_id=user, link_type='LOOKALIKE').all()
        assert len(links) == 2
