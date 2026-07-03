"""Tests analyse IA du graphe (Phase 2)."""
import json
from unittest.mock import patch

import pytest

from extensions import db
from models import User, Entity, EntityLink
from services.entity_merge import merge_entities
from services import graph_analysis


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


def _link(user_id, a, b, typ='REL', conf=0.6):
    db.session.add(EntityLink(user_id=user_id, source_id=a.id, target_id=b.id,
                              link_type=typ, confidence=conf))


def test_payload_includes_clusters(app, user):
    with app.app_context():
        a = _mk(user, 'username', 'benji')
        b = _mk(user, 'email', 'benji@x.com')
        c = _mk(user, 'domain', 'x.com')
        _link(user, a, c)
        db.session.commit()
        merge_entities(user, a.id, b.id)  # crée le cluster (lien MEME_PERSONNE)
        payload = graph_analysis.build_analysis_payload(user, a.id)
        assert payload['cible'] == 'benji'
        assert payload['nb_entites'] >= 3
        clusters = payload['personnes_regroupees']
        assert any(set(c) == {'benji', 'benji@x.com'} for c in clusters)


def test_analyze_graph_uses_ai(app, user):
    with app.app_context():
        a = _mk(user, 'username', 'benji')
        b = _mk(user, 'domain', 'x.com')
        _link(user, a, b)
        db.session.commit()
        ai_out = json.dumps({
            'synthese': 'Analyse test.',
            'incoherences': [{'observation': 'X', 'gravite': 'moyenne'}],
            'pistes': [{'action': 'whois x.com', 'raison': 'r', 'priorite': 1}],
        })
        with patch('services.llm.llm_chat', return_value=ai_out):
            out = graph_analysis.analyze_graph(user, a.id)
        assert out['source'] == 'ia'
        assert out['synthese'] == 'Analyse test.'
        assert out['incoherences'][0]['gravite'] == 'moyenne'
        assert out['pistes'][0]['action'] == 'whois x.com'


def test_analyze_graph_fallback_without_llm(app, user, monkeypatch):
    for p in ('GROQ_API_KEY', 'GEMINI_API_KEY', 'CEREBRAS_API_KEY', 'OPENROUTER_API_KEY'):
        monkeypatch.delenv(p, raising=False)
    with app.app_context():
        a = _mk(user, 'email', 'benji@x.com')
        db.session.commit()
        out = graph_analysis.analyze_graph(user, a.id)
        assert out['source'] == 'fallback'
        assert 'synthese' in out
        assert isinstance(out['pistes'], list)


def test_analyze_empty_graph(app, user):
    with app.app_context():
        out = graph_analysis.analyze_graph(user, 999999)
        assert 'error' in out


def test_compare_graphs_shared_identifiers(app, user, monkeypatch):
    for p in ('GROQ_API_KEY', 'GEMINI_API_KEY', 'CEREBRAS_API_KEY', 'OPENROUTER_API_KEY'):
        monkeypatch.delenv(p, raising=False)  # force fallback déterministe
    with app.app_context():
        # graphe A autour de benji
        a = _mk(user, 'username', 'benji')
        a2 = _mk(user, 'email', 'benji@x.com')
        _link(user, a, a2)
        # graphe B autour de benjidupont, partage le token 'benji' via email
        b = _mk(user, 'username', 'benjidupont')
        b2 = _mk(user, 'email', 'benji@y.com')
        _link(user, b, b2)
        db.session.commit()
        out = graph_analysis.compare_graphs(user, a.id, b.id)
        assert out['source'] == 'fallback'
        assert 'benji' in out['identifiants_partages']
        assert out['similarite'] > 0
        assert out['analyse_ia']['verdict'] in ('meme_personne', 'lies', 'distincts', 'incertain')
