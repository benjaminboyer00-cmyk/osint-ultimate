"""Tests timeline interactive — Phase 6 V7."""
from datetime import datetime
from unittest.mock import MagicMock, patch

from services.timeline import (
    _parse_date,
    _collect_dated_events,
    build_timeline,
    GROUPS,
)


def test_parse_date_iso():
    assert _parse_date('2024-06-15T10:00:00') is not None
    assert _parse_date('20240615') == '2024-06-15'


def test_parse_date_wayback():
    assert _parse_date('20190315') == '2019-03-15'


def test_collect_wayback_snapshots():
    payload = {
        'Module: wayback': {
            'Snapshots': [
                {'Date': '20200101', 'URL': 'https://ex.com', 'Lien archive': 'http://archive.org/x'},
            ],
        },
    }
    seq = [0]
    evs = _collect_dated_events(1, payload, seq)
    assert any(e['type'] == 'wayback' for e in evs)


def test_collect_whois():
    payload = {'WHOIS': {'Création': '2020-01-15', 'Registrar': 'Test'}}
    seq = [0]
    evs = _collect_dated_events(2, payload, seq)
    assert any(e['type'] == 'whois' for e in evs)


def test_build_timeline_none():
    with patch('services.timeline.Entity') as Ent:
        Ent.query.filter_by.return_value.first.return_value = None
        assert build_timeline(1, 10) is None


def test_build_timeline_structure():
    root = MagicMock(
        id=1, user_id=10, entity_type='domain', value='example.com',
        created_at=datetime(2024, 1, 1),
    )
    with patch('services.timeline.Entity') as Ent:
        Ent.query.filter_by.return_value.first.return_value = root
        with patch('services.correlation.build_graph_json', return_value={'nodes': [], 'edges': []}):
            with patch('services.timeline._related_scans', return_value=[]):
                with patch('services.timeline.db') as mock_db:
                    mock_db.session.get.return_value = None
                    with patch('services.timeline.EntityLink') as EL:
                        EL.query.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
                        data = build_timeline(1, 10)
    assert data is not None
    assert data['groups'] == GROUPS
    assert isinstance(data['items'], list)
