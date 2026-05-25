"""Tests connecteur Instagram (instaloader mocké)."""
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def mock_profile():
    profile = MagicMock()
    profile.username = 'alice'
    profile.full_name = 'Alice Test'
    profile.biography = 'Ma bio OSINT'
    profile.profile_pic_url = 'https://cdn.example/pic.jpg'
    profile.followers = 1000
    profile.followees = 50
    profile.mediacount = 42
    profile.is_private = False
    profile.is_verified = True
    profile.followed_by_viewer = False
    profile.userid = 12345
    post = MagicMock()
    post.shortcode = 'ABC123'
    post.caption = 'Hello world'
    post.date_utc = MagicMock(isoformat=lambda: '2026-01-01T12:00:00')
    profile.get_posts.return_value = iter([post])
    return profile


def test_to_scan_result_success():
    from connectors.instagram import _to_scan_result

    raw = {
        'success': True,
        'username': 'alice',
        'full_name': 'Alice',
        'biography': 'Bio test',
        'followers': 10,
        'following': 2,
        'posts_count': 5,
        'is_private': False,
        'is_verified': False,
        'profile_pic_url': 'https://x/p.jpg',
        'recent_posts': [{'url': 'https://instagram.com/p/x/', 'caption': 'Hi', 'date': '2026-01-01'}],
        'recent_stories': [],
    }
    out = _to_scan_result(raw)
    assert out['Bio'] == 'Bio test'
    assert out['Posts récents'][0]['URL'].endswith('/')


@patch('connectors.instagram.INSTALOADER_AVAILABLE', True)
@patch('connectors.instagram.Instaloader')
@patch('connectors.instagram.Profile')
def test_scan_public_profile(MockProfile, MockLoader, mock_profile):
    from connectors.instagram import scan

    ctx = MagicMock()
    ctx.is_logged_in = False
    loader = MockLoader.return_value
    loader.context = ctx
    MockProfile.from_username.return_value = mock_profile

    with patch.dict('os.environ', {}, clear=False):
        out = scan('alice', {})
    assert out is not None
    assert out['Nom complet'] == 'Alice Test'
    assert out['Bio'] == 'Ma bio OSINT'
    assert len(out.get('Posts récents', [])) == 1
    assert 'Stories actives' not in out or not out.get('Stories actives')


@patch('connectors.instagram.INSTALOADER_AVAILABLE', True)
@patch('connectors.instagram.Instaloader')
@patch('connectors.instagram.Profile')
def test_scan_profile_not_found(MockProfile, MockLoader):
    from connectors.instagram import ProfileNotExistsException, scan

    MockProfile.from_username.side_effect = ProfileNotExistsException('nope')
    out = scan('unknown_user_xyz', {})
    assert out['Erreur'] == 'Profil introuvable'


def test_inject_rotating_proxy_from_proxy_list():
    from connectors.instagram import inject_rotating_proxy

    opts = {'_proxy_list': 'http://a:1,http://b:2'}
    with patch('connectors.instagram.random.choice', return_value='http://b:2'):
        proxy = inject_rotating_proxy(opts)
    assert proxy == 'http://b:2'
    assert opts['_proxy_for_run'] == 'http://b:2'


def test_proxy_array_merges_ig_proxy_url():
    from connectors.instagram import _proxy_array

    with patch.dict('os.environ', {'PROXY_LIST': 'http://a', 'IG_PROXY_URL': 'http://extra'}):
        arr = _proxy_array({})
    assert 'http://a' in arr
    assert 'http://extra' in arr
