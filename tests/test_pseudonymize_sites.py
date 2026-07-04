"""Vérifie qu'aucune donnée réelle ne fuit vers l'IA aux 4 sites d'appel."""
from unittest.mock import patch

import pytest


def test_narrative_report_pseudonymized():
    from services import groq
    captured = {}

    def fake_req(messages, api_key=None, json_mode=False):
        captured['content'] = ' '.join(m['content'] for m in messages)
        return '## Synthèse\n\nDOMAIN_1 est hébergé chez AWS. Contact EMAIL_2.'

    data = {
        'dossier': {'root_entity': 'benjamin.boyer00.com'},
        'entities': [{'entity_type': 'email', 'value': 'contact@benjamin.boyer00.com'}],
        'links': [], 'sources': [],
    }
    facts = {'cible': 'benjamin.boyer00.com',
             'infrastructure': ['Domaine benjamin.boyer00.com hébergé chez AWS']}
    with patch('services.groq._groq_request', side_effect=fake_req):
        out = groq.generate_narrative_report(data, technical_facts=facts)
    # rien de réel dans le prompt
    assert 'benjamin.boyer00.com' not in captured['content']
    assert 'contact@benjamin.boyer00.com' not in captured['content']
    assert 'DOMAIN_' in captured['content']
    # sortie ré-hydratée
    assert 'benjamin.boyer00.com' in out


def test_investigation_agent_pseudonymized_and_rehydrated():
    from services import investigation_agent as ia
    captured = {}

    def fake_chat(prompt, system=None):
        captured['prompt'] = prompt
        # l'IA répond en jetons
        return '{"action":"whois","params":{"target":"DOMAIN_1"},"reason":"x"}'

    with patch('services.investigation_agent.chat_completion', side_effect=fake_chat):
        plan = ia.plan_next_action('analyse le site example.com stp', [], 1)
    assert 'example.com' not in captured['prompt']
    assert 'DOMAIN_' in captured['prompt']
    # la cible est ré-hydratée -> le scan tournera sur la vraie valeur
    assert plan['action'] == 'whois'
    assert plan['params']['target'] == 'example.com'


def test_investigation_chat_pseudonymized():
    from services import investigation_ai as iai
    captured = {}

    def fake_chat(prompt, system=None):
        captured['prompt'] = prompt
        return 'EMAIL_1 semble lié.\nACTIONS:\n→ Vérifier EMAIL_1'

    with patch('services.investigation_ai.chat_completion', side_effect=fake_chat):
        out = iai.investigate_step('que sais-tu sur jean@secret.com ?',
                                   {'last_target': 'jean@secret.com'})
    assert 'jean@secret.com' not in captured['prompt']
    assert 'secret.com' not in captured['prompt']
    assert 'EMAIL_' in captured['prompt']
    # réponse + actions ré-hydratées
    assert 'jean@secret.com' in out['reply']
    assert any('jean@secret.com' in a for a in out['actions'])


@pytest.fixture
def app_client():
    from app import app
    from extensions import db
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    with app.app_context():
        db.create_all()
        yield app


def test_ai_summary_route_pseudonymized(app_client):
    captured = {}

    def fake_summarize(text, api_key=None, system=None):
        captured['text'] = text if isinstance(text, str) else str(text)
        return 'Résumé : IP_1 expose le port 22.'

    client = app_client.test_client()
    with patch('app.summarize_osint_with_groq', side_effect=fake_summarize):
        r = client.post('/ai-summary', json={
            'result': 'Scan IP 93.184.216.34 : email admin@evil.com trouvé.',
        })
    assert r.status_code == 200
    assert '93.184.216.34' not in captured['text']
    assert 'admin@evil.com' not in captured['text']
    assert 'IP_' in captured['text'] or 'EMAIL_' in captured['text']
