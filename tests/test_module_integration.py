"""QA d'intégration : aucun module référencé (UI/suggestions) ne doit être
inexistant, et le pipeline de scan complet doit corréler un nouvel outil."""
import json
import re
from unittest.mock import patch

import pytest

from extensions import db
from models import User, Scan, Entity
from scans.registry import SCAN_FUNCTIONS


def test_ui_buttons_map_to_registered_modules():
    html = open('templates/index.html', encoding='utf-8').read()
    ui = set(re.findall(r'data-m="([a-z_]+)"', html))
    dangling = ui - set(SCAN_FUNCTIONS)
    assert not dangling, f'Boutons UI sans module: {dangling}'


def test_graph_suggestions_map_to_registered_modules():
    from services.correlation import get_rebound_suggestions  # noqa: F401
    corr = open('services/correlation.py', encoding='utf-8').read()
    # bloc de la fonction de suggestions uniquement
    suggested = set(re.findall(r"'module':\s*'([a-z_]+)'", corr))
    dangling = suggested - set(SCAN_FUNCTIONS)
    assert not dangling, f'Suggestions sans module: {dangling}'


def test_new_tools_registered():
    for t in ('subdomains', 'typosquat', 'reverse_ip'):
        assert t in SCAN_FUNCTIONS and callable(SCAN_FUNCTIONS[t])


@pytest.fixture
def user(app):
    with app.app_context():
        u = User(username='u1', email='u1@t.co')
        u.set_password('x')
        db.session.add(u)
        db.session.commit()
        yield u.id


def test_full_scan_pipeline_subdomains(app, user):
    """Bout en bout : process_scan_by_id -> module -> corrélation -> entités."""
    from services.scan_runner import process_scan_by_id
    with app.app_context():
        scan = Scan(user_id=user, module='subdomains', target='example.com',
                    status='pending')
        db.session.add(scan)
        db.session.commit()
        sid = scan.id

    fake = {'Domaine': 'example.com', 'Sous-domaines trouvés': 2,
            'Liste': ['api.example.com', 'mail.example.com']}
    with patch('connectors.crtsh.search_subdomains', return_value=fake):
        process_scan_by_id(sid, app, socketio=None, fernet=None)

    with app.app_context():
        done = db.session.get(Scan, sid)
        assert done.status == 'completed'
        vals = {e.value for e in Entity.query.filter_by(user_id=user).all()}
        assert {'example.com', 'api.example.com', 'mail.example.com'} <= vals
