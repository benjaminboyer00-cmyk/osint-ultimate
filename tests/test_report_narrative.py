"""Tests rapport narratif IA (Phase 3 V7)."""
import json
from unittest.mock import patch, MagicMock

from services.report_data import build_report_data, pick_anchor_scan
from services.groq import generate_narrative_report, markdown_to_html, NARRATIVE_STYLES


def test_report_data_structure():
    ent = MagicMock(
        id=1, user_id=10, entity_type='email', value='test@example.com',
        created_at=None, source_scan_id=None,
    )
    dossier = {
        'entity': {'id': 1, 'type': 'email', 'value': 'test@example.com'},
        'title': 'Dossier test',
        'scans_count': 1,
        'links_count': 0,
        'timeline': [],
        'web_history': [],
    }
    with patch('services.report_data.build_dossier', return_value=dossier):
        with patch('services.report_data.Entity') as Ent:
            Ent.query.filter_by.return_value.first.return_value = ent
            with patch('services.report_data.build_graph_json', return_value={
                'nodes': [{'id': '1', 'type': 'email', 'value': 'test@example.com'}],
                'edges': [],
                'root_id': '1',
            }):
                with patch('services.report_data.build_entity_links_json', return_value={'links': []}):
                    with patch('services.report_data.db') as mock_db:
                        mock_db.session.get.return_value = ent
                        with patch('services.report_data._collect_related_scans', return_value=[
                            {'id': 5, 'module': 'email', 'target': 'test@example.com', 'sections': ['MX']},
                        ]):
                            data = build_report_data(1, 10)
    assert data is not None
    assert data['dossier']['entity_id'] == 1
    assert isinstance(data['entities'], list)
    assert isinstance(data['links'], list)
    assert 'scans' in data
    assert 'sources' in data


def test_generate_narrative_mock():
    sample = {'dossier': {'title': 'Test'}, 'entities': [], 'links': []}
    facts = {'cible': 'example.com', 'infrastructure': ['DNS A: 1.2.3.4'], 'reseau': [], 'identite': [], 'securite': [], 'lacunes': []}
    with patch('services.groq._groq_request', return_value='## Synthèse exécutive\n\nTest.'):
        md = generate_narrative_report(sample, style='executive', technical_facts=facts)
    assert 'Synthèse' in md or 'exécutive' in md


def test_markdown_to_html():
    html = markdown_to_html('## Titre\n\nParagraphe **gras**.')
    assert 'Titre' in html or 'titre' in html.lower()


def test_narrative_styles_keys():
    assert 'executive' in NARRATIVE_STYLES
    assert 'legal' in NARRATIVE_STYLES


def test_pick_anchor_scan_none():
    with patch('services.report_data.Entity') as Ent:
        Ent.query.filter_by.return_value.first.return_value = None
        assert pick_anchor_scan(99, 10) is None
