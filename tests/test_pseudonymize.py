"""Tests pseudonymisation avant envoi LLM (confidentialité)."""
from unittest.mock import patch
import json

import pytest

from extensions import db
from models import User, Entity, EntityLink
from services.pseudonymize import Pseudonymizer
from services import graph_analysis


def test_token_stable_and_typed():
    p = Pseudonymizer()
    t1 = p.token_for('benji', 'username')
    t2 = p.token_for('benji', 'username')      # même valeur -> même jeton
    t3 = p.token_for('x@y.com', 'email')
    assert t1 == t2
    assert t1.startswith('USERNAME_')
    assert t3.startswith('EMAIL_')
    assert t1 != t3


def test_rehydrate_roundtrip():
    p = Pseudonymizer()
    tu = p.token_for('benji', 'username')
    te = p.token_for('benji@x.com', 'email')
    ai_reply = {
        'synthese': f'{tu} est lié à {te}.',
        'liens': [{'de': tu, 'vers': te}],
    }
    out = p.rehydrate(ai_reply)
    assert out['synthese'] == 'benji est lié à benji@x.com.'
    assert out['liens'][0]['de'] == 'benji'
    assert out['liens'][0]['vers'] == 'benji@x.com'


def test_rehydrate_no_partial_token_collision():
    p = Pseudonymizer()
    toks = [p.token_for(f'user{i}', 'username') for i in range(12)]
    # USERNAME_1 ne doit pas s'insérer dans USERNAME_10/11/12
    reply = {'t': ' '.join(toks)}
    out = p.rehydrate(reply)
    assert out['t'] == ' '.join(f'user{i}' for i in range(12))


@pytest.fixture
def user(app):
    with app.app_context():
        u = User(username='u1', email='u1@t.co', password_hash='x')
        db.session.add(u)
        db.session.commit()
        yield u.id


def test_analyze_graph_never_sends_real_values(app, user):
    """Le prompt envoyé au LLM ne doit contenir AUCUNE valeur réelle."""
    with app.app_context():
        a = Entity(user_id=user, entity_type='username', value='benji')
        b = Entity(user_id=user, entity_type='email', value='benji@secret.com')
        db.session.add_all([a, b]); db.session.flush()
        db.session.add(EntityLink(user_id=user, source_id=a.id, target_id=b.id,
                                  link_type='PSEUDO_LOCAL', confidence=0.6))
        db.session.commit()

        captured = {}

        def fake_chat_json(prompt, system=None):
            captured['prompt'] = prompt
            captured['system'] = system
            # l'IA répond en jetons (comme le vrai modèle le ferait)
            return {'synthese': 'USERNAME_1 lié à EMAIL_2.',
                    'incoherences': [], 'liens_hypothetiques': [], 'pistes': []}

        with patch('services.llm.chat_json', fake_chat_json):
            out = graph_analysis.analyze_graph(user, a.id)

        # 1) aucune valeur réelle n'a fuité dans le prompt
        assert 'benji' not in captured['prompt']
        assert 'secret.com' not in captured['prompt']
        assert 'USERNAME_' in captured['prompt'] and 'EMAIL_' in captured['prompt']
        # 2) la réponse rendue à l'utilisateur est ré-hydratée
        assert out['source'] == 'ia'
        assert 'benji' in out['synthese']
        assert 'benji@secret.com' in out['synthese']
