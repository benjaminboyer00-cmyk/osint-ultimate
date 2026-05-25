"""Tests scans sociaux et rattachement dossier."""
from unittest.mock import MagicMock, patch

from services.social_fetch import parse_instagram_profile_html, parse_instagram_api_json
from services.dossier_scans import link_scans_to_dossier, _target_values_for_dossier


def test_parse_instagram_api_json():
    data = {
        'data': {
            'user': {
                'username': 'testuser',
                'full_name': 'Test User',
                'biography': 'Bio',
                'edge_followed_by': {'count': 100},
                'edge_follow': {'count': 50},
                'edge_owner_to_timeline_media': {'count': 10},
                'is_verified': True,
                'is_private': False,
            },
        },
    }
    out = parse_instagram_api_json(data)
    assert out['Nom complet'] == 'Test User'
    assert out['Followers'] == 100
    assert '✓' in out['Vérifié']


def test_parse_instagram_og_description():
    from services.social_fetch import parse_instagram_og_meta

    desc = (
        '882 Followers, 1,010 Following, 3 Posts - See Instagram photos and videos '
        'from Vivie (@his.vihc)'
    )
    out = parse_instagram_og_meta(
        'Vivie (@his.vihc) • Instagram photos and videos',
        desc,
        'his.vihc',
    )
    assert out['Followers'] == 882
    assert out['Following'] == 1010
    assert out['Publications'] == 3


def test_parse_instagram_html_counts():
    html = (
        '"edge_followed_by":{"count":42},'
        '"edge_follow":{"count":7},'
        '"full_name":"Alice"'
    )
    out = parse_instagram_profile_html(html, 'alice')
    assert out.get('Followers') == 42
    assert out.get('Nom complet') == 'Alice'
    assert out.get('Profil', '').endswith('/alice/')


def test_link_scans_to_dossier():
    scan = MagicMock(
        id=99, user_id=10, status='completed', target='targetuser',
        root_entity_id=None, result_json='{}',
    )
    with patch('services.dossier_scans._target_values_for_dossier', return_value={'targetuser', '@targetuser'}):
        with patch('services.dossier_scans.db') as db:
            q = db.session.query.return_value
            q.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [scan]
            n = link_scans_to_dossier(25, 10)
    assert n == 1
    assert scan.root_entity_id == 25


def test_target_values_for_dossier():
    ent = MagicMock(id=1, user_id=10, value='UserName', entity_type='username')
    with patch('services.dossier_scans.db') as db:
        db.session.get.return_value = ent
        with patch('services.dossier_scans.EntityLink') as Link:
            Link.query.filter.return_value.all.return_value = []
            vals = _target_values_for_dossier(1, 10)
    assert 'username' in vals
    assert '@username' in vals
