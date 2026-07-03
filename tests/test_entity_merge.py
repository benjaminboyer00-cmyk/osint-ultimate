"""Tests fusion d'entités (Phase 1 — clusters « même personne »)."""
import pytest

from extensions import db
from models import User, Entity, EntityLink
from services.entity_merge import (
    merge_entities, unmerge_entities, get_person_cluster,
    suggest_person_merges, MERGE_LINK_TYPE,
)


@pytest.fixture
def user(app):
    with app.app_context():
        u = User(username='u1', email='u1@t.co', password_hash='x')
        db.session.add(u)
        db.session.commit()
        yield u.id


def _mk(user_id, etype, value):
    e = Entity(user_id=user_id, entity_type=etype, value=value)
    db.session.add(e)
    db.session.flush()
    return e


def test_merge_creates_link_and_cluster(app, user):
    with app.app_context():
        a = _mk(user, 'username', 'benji')
        b = _mk(user, 'username', 'benjamin.boyer00')
        db.session.commit()
        out = merge_entities(user, a.id, b.id)
        assert out['status'] == 'merged'
        assert out['cluster']['size'] == 2
        link = EntityLink.query.filter_by(link_type=MERGE_LINK_TYPE).one()
        assert {link.source_id, link.target_id} == {a.id, b.id}


def test_merge_is_idempotent(app, user):
    with app.app_context():
        a = _mk(user, 'username', 'benji')
        b = _mk(user, 'email', 'benji@x.com')
        db.session.commit()
        merge_entities(user, a.id, b.id)
        out = merge_entities(user, b.id, a.id)  # ordre inversé
        assert out['status'] == 'exists'
        assert EntityLink.query.filter_by(link_type=MERGE_LINK_TYPE).count() == 1


def test_cluster_is_transitive(app, user):
    with app.app_context():
        a = _mk(user, 'username', 'benji')
        b = _mk(user, 'email', 'benji@x.com')
        c = _mk(user, 'phone', '+33600000000')
        db.session.commit()
        merge_entities(user, a.id, b.id)
        merge_entities(user, b.id, c.id)
        cluster = get_person_cluster(user, a.id)
        assert cluster['size'] == 3
        assert {m['id'] for m in cluster['members']} == {a.id, b.id, c.id}


def test_unmerge_removes_link(app, user):
    with app.app_context():
        a = _mk(user, 'username', 'benji')
        b = _mk(user, 'username', 'benjamin.boyer00')
        db.session.commit()
        merge_entities(user, a.id, b.id)
        out = unmerge_entities(user, a.id, b.id)
        assert out['status'] == 'unmerged'
        assert EntityLink.query.filter_by(link_type=MERGE_LINK_TYPE).count() == 0
        assert get_person_cluster(user, a.id)['size'] == 1


def test_cannot_merge_self_or_foreign(app, user):
    with app.app_context():
        a = _mk(user, 'username', 'benji')
        db.session.commit()
        with pytest.raises(ValueError):
            merge_entities(user, a.id, a.id)
        with pytest.raises(ValueError):
            merge_entities(user, a.id, 999999)


def test_suggestions_find_similar_and_exclude_cluster(app, user):
    with app.app_context():
        root = _mk(user, 'username', 'benjamin')
        email = _mk(user, 'email', 'benjamin@gmail.com')  # même token, autre type
        similar = _mk(user, 'username', 'benjamiin')       # proche
        _mk(user, 'domain', 'unrelated-site.com')          # rien à voir
        db.session.commit()
        sugs = suggest_person_merges(user, root.id)
        ids = {s['entity']['id'] for s in sugs}
        assert email.id in ids
        assert similar.id in ids
        # une fois fusionnée, l'email ne doit plus être suggéré
        merge_entities(user, root.id, email.id)
        sugs2 = suggest_person_merges(user, root.id)
        assert email.id not in {s['entity']['id'] for s in sugs2}
