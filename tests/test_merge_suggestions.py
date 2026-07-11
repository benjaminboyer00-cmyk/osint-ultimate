"""Tests du moteur de fusion intelligent (diminutifs + signal structurel)."""
import pytest

from extensions import db
from models import User, Entity, EntityLink
from services.entity_merge import suggest_person_merges


@pytest.fixture
def user(app):
    with app.app_context():
        u = User(username='u1', email='u1@t.co')
        u.set_password('x')
        db.session.add(u)
        db.session.commit()
        yield u.id


def _mk(uid, t, v):
    e = Entity(user_id=uid, entity_type=t, value=v)
    db.session.add(e)
    db.session.flush()
    return e


def _link(uid, a, b, t='REL'):
    db.session.add(EntityLink(user_id=uid, source_id=a.id, target_id=b.id, link_type=t))


def test_nickname_diminutive(app, user):
    with app.app_context():
        benji = _mk(user, 'username', 'benji')
        benjamin = _mk(user, 'username', 'benjamin')
        db.session.commit()
        sugs = suggest_person_merges(user, benji.id)
        match = [s for s in sugs if s['entity']['id'] == benjamin.id]
        assert match and 'iminutif' in match[0]['reason']
        assert match[0]['score'] >= 0.85


def test_trailing_digits_ignored(app, user):
    with app.app_context():
        a = _mk(user, 'username', 'benjamin.boyer00')
        b = _mk(user, 'username', 'benjaminboyer')
        db.session.commit()
        sugs = suggest_person_merges(user, a.id)
        assert any(s['entity']['id'] == b.id for s in sugs)


def test_structural_shared_connection_boosts(app, user):
    with app.app_context():
        a = _mk(user, 'username', 'xkcd_fan_92')
        b = _mk(user, 'username', 'randomdude_ab')   # noms non similaires
        common = _mk(user, 'email', 'shared@x.com')
        _link(user, a, common)
        _link(user, b, common)                        # connexion commune
        db.session.commit()
        sugs = suggest_person_merges(user, a.id)
        match = [s for s in sugs if s['entity']['id'] == b.id]
        # sans le signal structurel, ces deux pseudos ne seraient jamais suggérés
        assert match and 'commune' in match[0]['reason']
