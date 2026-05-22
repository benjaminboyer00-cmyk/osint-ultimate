"""Tests Phase 8 — collaboration."""
from unittest.mock import MagicMock, patch

from services.correlation import _entities_equivalent as corr_equiv


def test_entities_equivalent():
    a = MagicMock(id=1, entity_type='domain', value='example.com')
    b = MagicMock(id=2, entity_type='unknown', value='https://example.com')
    assert corr_equiv(a, b) is True


def test_role_levels():
    from services.dossier_access import _role_level
    assert _role_level('editor') > _role_level('reader')


def test_invite_requires_admin():
    from services.collaboration import invite_collaborator
    with patch('services.dossier_access.get_dossier_context', return_value=None):
        try:
            invite_collaborator(10, 2, 'a@b.com', 'reader')
            assert False, 'should raise'
        except ValueError as e:
            assert 'Droits' in str(e) or 'admin' in str(e).lower()


def test_invite_share_url():
    from services.collaboration import invite_share_url, invite_share_path
    assert invite_share_path(12) == '/invitations#inv-12'
    assert invite_share_url(12, 'https://app.example.com') == 'https://app.example.com/invitations#inv-12'
