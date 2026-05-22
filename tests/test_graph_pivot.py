"""Tests pivot graphe (Phase 2)."""
from unittest.mock import patch, MagicMock

from services.graph_pivot import modules_for_entity, PIVOT_MODULES


def test_modules_for_email():
    with patch('app.SCAN_FUNCTIONS', {
        'email': None, 'dehashed': None, 'hunter': None, 'epieos': None,
    }):
        mods = modules_for_entity('email', 'user@example.com')
    assert 'email' in mods


def test_modules_for_ip():
    with patch('app.SCAN_FUNCTIONS', {
        'ip': None, 'otx': None, 'urlhaus': None, 'whois': None,
    }):
        mods = modules_for_entity('ip', '8.8.8.8')
    assert 'ip' in mods


def test_pivot_modules_mapping():
    assert 'sherlock' in PIVOT_MODULES['username']
    assert 'site' in PIVOT_MODULES['domain']


def test_launch_pivot_mock():
    ent = MagicMock(id=5, user_id=10, entity_type='email', value='a@test.com')
    with patch('services.graph_pivot.db') as mock_db:
        mock_db.session.get.return_value = ent
        with patch('app.run_scan_async', return_value=42) as mock_run:
            with patch('app.SCAN_FUNCTIONS', {
                'email': None, 'dehashed': None, 'hunter': None, 'epieos': None,
            }):
                from services.graph_pivot import launch_pivot
                out = launch_pivot(10, 5, root_entity_id=1)
    assert out['scan_id'] == 42
    assert out['status'] == 'started'
    assert mock_run.called
    call_kw = mock_run.call_args
    assert call_kw[0][0] == 'multi'
