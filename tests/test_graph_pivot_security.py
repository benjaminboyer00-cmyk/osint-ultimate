"""Tests des garde-fous d'autorisation du pivot de graphe (anti-IDOR)."""
from unittest.mock import patch, MagicMock

import pytest

from services.graph_pivot import launch_pivot


def test_pivot_entity_not_found():
    with patch('services.graph_pivot.db') as mdb:
        mdb.session.get.return_value = None
        with pytest.raises(ValueError, match='non trouvée'):
            launch_pivot(1, 99)


def test_pivot_denied_without_dossier_access():
    """Un utilisateur sans accès au dossier ne peut pas pivoter (IDOR)."""
    ent = MagicMock(id=5, user_id=10, entity_type='email', value='a@b.com')
    with patch('services.graph_pivot.db') as mdb:
        mdb.session.get.return_value = ent
        with patch('services.dossier_access.get_dossier_context', return_value=None):
            with pytest.raises(ValueError, match='Droits'):
                launch_pivot(999, 5, root_entity_id=1)


def test_pivot_entity_outside_dossier():
    """Une entité hors du graphe du dossier est refusée."""
    ent = MagicMock(id=5, user_id=10, entity_type='email', value='a@b.com')
    ctx = {'owner_user_id': 10, 'is_owner': True, 'can_edit': True}
    with patch('services.graph_pivot.db') as mdb:
        mdb.session.get.return_value = ent
        with patch('services.dossier_access.get_dossier_context', return_value=ctx):
            with patch('services.correlation.build_graph_json',
                       return_value={'nodes': [{'id': '7'}], 'edges': []}):
                with pytest.raises(ValueError, match='hors du dossier'):
                    launch_pivot(10, 5, root_entity_id=1)


def test_pivot_happy_path_owner():
    ent = MagicMock(id=5, user_id=10, entity_type='email', value='a@b.com')
    ctx = {'owner_user_id': 10, 'is_owner': True, 'can_edit': True}
    with patch('services.graph_pivot.db') as mdb:
        mdb.session.get.return_value = ent
        with patch('services.dossier_access.get_dossier_context', return_value=ctx), \
             patch('services.correlation.build_graph_json',
                   return_value={'nodes': [{'id': '5'}], 'edges': []}), \
             patch('app.run_scan_async', return_value=77) as mrun, \
             patch('app.SCAN_FUNCTIONS', {'email': None, 'dehashed': None, 'hunter': None, 'epieos': None}):
            out = launch_pivot(10, 5, root_entity_id=5)
    assert out['scan_id'] == 77 and out['status'] == 'started'
    assert mrun.call_args[0][0] == 'multi'   # scan multi-modules
