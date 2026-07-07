"""Tests du graphe actif (créer un graphe puis y rattacher les recherches)."""
from unittest.mock import patch

import pytest

from extensions import db
from models import User, Entity, Investigation


@pytest.fixture
def user(app):
    with app.app_context():
        u = User(username='u1', email='u1@t.co')
        u.set_password('x')
        db.session.add(u)
        db.session.commit()
        yield u.id


def test_create_get_clear(app, user):
    from services.active_graph import create_graph, get_active, clear_active
    with app.test_request_context():
        g = create_graph(user, 'Enquête X')
        assert g['root_id'] and g['name'] == 'Enquête X'
        root = db.session.get(Entity, g['root_id'])
        assert root.entity_type == 'person' and root.user_id == user
        assert Investigation.query.filter_by(root_entity_id=g['root_id']).first()
        assert get_active(user)['root_id'] == g['root_id']
        clear_active()
        assert get_active(user) is None


def test_unique_name_collision(app, user):
    from services.active_graph import create_graph
    with app.test_request_context():
        a = create_graph(user, 'Dossier')
        b = create_graph(user, 'Dossier')
        assert a['name'] == 'Dossier'
        assert b['name'] == 'Dossier (2)'


def test_list_and_set_active(app, user):
    from services.active_graph import create_graph, set_active, list_graphs, clear_active
    with app.test_request_context():
        a = create_graph(user, 'A')
        b = create_graph(user, 'B')   # B devient actif
        graphs = list_graphs(user)
        assert {g['name'] for g in graphs} >= {'A', 'B'}
        assert any(g['active'] and g['name'] == 'B' for g in graphs)
        set_active(user, a['root_id'])
        assert any(g['active'] and g['name'] == 'A' for g in list_graphs(user))
        # entité d'un autre user refusée
        clear_active()
        assert set_active(user, 999999) is None


def test_scan_route_attaches_active_graph(app, user):
    """POST /scan sans root explicite doit rattacher le graphe actif."""
    from services.active_graph import create_graph
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user)  # login flask-login
    with app.test_request_context():
        g = create_graph(user, 'Active')
    with client.session_transaction() as sess:
        sess['active_graph_root'] = g['root_id']

    captured = {}

    def fake_run(module, target, options=None, user_id=None, mode='expert', **kw):
        captured['options'] = options
        captured['module'] = module
        return 4242

    with patch('app.run_scan_async', side_effect=fake_run):
        r = client.post('/scan', json={'module': 'whois', 'target': 'example.com'})
    assert r.status_code == 200
    assert captured['options'].get('_root_entity_id') == g['root_id']
