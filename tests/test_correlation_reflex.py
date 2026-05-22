"""Tests anti-liens réflexifs."""
from unittest.mock import MagicMock, patch

from services.correlation import _entities_equivalent, _link, _normalize_domain_value


def test_normalize_domain():
    assert _normalize_domain_value('https://www.Example.COM/path') == 'example.com'


def test_entities_equivalent_same_domain():
    a = MagicMock(id=1, entity_type='domain', value='example.com')
    b = MagicMock(id=2, entity_type='unknown', value='https://example.com')
    assert _entities_equivalent(a, b) is True


def test_link_skips_reflexive():
    ent = MagicMock(id=5, entity_type='domain', value='x.com')
    with patch('services.link_scoring.upsert_link_scored') as upsert:
        with patch('services.correlation.EntityLink') as EL:
            EL.query.filter_by.return_value.first.return_value = None
            _link(ent, ent, 'ENRICHIT', 'proof', 1, 1)
    upsert.assert_not_called()
    EL.query.filter_by.assert_not_called()
