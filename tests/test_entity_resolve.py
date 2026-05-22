"""Tests déduplication entités (entity_resolve)."""
from unittest.mock import MagicMock, patch

from services.entity_resolve import get_or_create_entity, find_entity_by_type_value


def test_get_or_create_reuses_exact_match():
    existing = MagicMock(id=42, entity_type='email', value='a@b.com')
    with patch('services.entity_resolve.find_entity_by_type_value', return_value=existing):
        out = get_or_create_entity(1, 'email', 'a@b.com', scan_id=9)
    assert out.id == 42


def test_get_or_create_uses_fuzzy_before_insert():
    fuzzy = MagicMock(id=7, entity_type='email', value='user@example.com')
    with patch('services.entity_resolve.find_entity_by_type_value', return_value=None), \
         patch('services.entity_resolve.find_entity_for_target', return_value=fuzzy):
        out = get_or_create_entity(1, 'email', 'user@example.com', scan_id=1, module='email')
    assert out.id == 7


def test_find_entity_domain_equivalence():
    ent = MagicMock(id=3, entity_type='unknown', value='example.com')
    with patch('services.entity_resolve.db') as mock_db:
        q = MagicMock()
        mock_db.session.query.return_value = q
        q.filter_by.return_value.first.side_effect = [None, ent]
        found = find_entity_by_type_value(1, 'domain', 'https://www.example.com')
    assert found is ent
